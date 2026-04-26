package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/c2FmZQ/distfs/pkg/metadata"
)

// VerifyTimelineReceipt checks a signed response receipt against a random follower node.
func (c *Client) VerifyTimelineReceipt(ctx context.Context, res metadata.SealedResponse) error {
	// Fetch anchored node list from registry
	nodes, err := c.getRegistryNodes(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch anchored cluster nodes from registry: %w", err)
	}

	// Filter followers
	var followers []metadata.ClusterNode
	for _, n := range nodes {
		// We can verify against any node, but usually we choose one that is NOT the current leader.
		// However, in our system, c.serverAddr is the leader.
		cleanU := strings.TrimRight(n.Address, "/")
		if cleanU != strings.TrimRight(c.serverAddr, "/") {
			followers = append(followers, n)
		}
	}

	if len(followers) == 0 {
		return nil // Vacuously true
	}

	// Pick a random follower
	target := followers[rand.Intn(len(followers))]

	req := metadata.VerifyTimelineRequest{
		SealedResponse:   res.Sealed,
		TimelineIndex:    res.TimelineIndex,
		ClusterStateHash: res.ClusterStateHash,
		BindingSignature: res.BindingSignature,
	}
	body, _ := json.Marshal(req)

	// Construct URL
	targetURL, err := url.Parse(target.Address)
	if err != nil {
		return err
	}
	// Ensure consistent scheme with leader
	leaderURL, _ := url.Parse(c.serverAddr)
	if targetURL.Scheme == "" {
		targetURL.Scheme = leaderURL.Scheme
	}

	verifyURL := targetURL.JoinPath("/v1/timeline")

	maxRetries := 5
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		hreq, err := http.NewRequestWithContext(ctx, "POST", verifyURL.String(), bytes.NewReader(body))
		if err != nil {
			return err
		}
		hreq.Header.Set("Content-Type", "application/json")

		resp, err := c.httpCli.Do(hreq)
		if err != nil {
			lastErr = err
			time.Sleep(200 * time.Millisecond)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return nil // Verified!
		}
		if resp.StatusCode == http.StatusTooEarly {
			// Lagging follower, retry
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if resp.StatusCode == http.StatusConflict {
			var apiErr metadata.APIErrorResponse
			if err := json.NewDecoder(resp.Body).Decode(&apiErr); err == nil && apiErr.Code == metadata.ErrCodeCryptographicFork {
				return metadata.ErrCryptographicFork
			}
			return metadata.ErrCryptographicFork // Fallback if decoding fails but status is 409
		}

		var apiErr metadata.APIErrorResponse
		json.NewDecoder(resp.Body).Decode(&apiErr)
		return fmt.Errorf("timeline verification failed at node %s: %s", target.ID, apiErr.Message)
	}

	return fmt.Errorf("failed to verify timeline receipt against %s: %v", target.ID, lastErr)
}

// VerifyTimeline checks that the Leader's current timeline is not isolated.
// This prevents Split-View/Equivocation attacks.
func (c *Client) VerifyTimeline(ctx context.Context) error {
	// Fetch anchored node list from registry
	nodes, err := c.getRegistryNodes(ctx)
	if err != nil {
		// If registry is not available, we can't perform Byzantine-resistant quorum check.
		// For now, we allow fallback to single node if no registry is found, or return error.
		return fmt.Errorf("failed to fetch anchored cluster nodes from registry: %w", err)
	}

	return c.VerifyTimelineWithNodes(ctx, nodes)
}

// VerifyTimelineWithNodes performs the timeline verification against a specific list of nodes.
func (c *Client) VerifyTimelineWithNodes(ctx context.Context, nodes []metadata.ClusterNode) error {
	var leaderResp metadata.TimelineResponse
	_, _, err := c.doRequest(ctx, "GET", "/v1/timeline", nil, requestOptions{skipControl: true, retry: true}, &leaderResp)
	if err != nil {
		return fmt.Errorf("failed to fetch timeline from leader: %w", err)
	}

	c.sessionMu.RLock()
	st := c.sessionToken
	c.sessionMu.RUnlock()

	// Filter followers from anchored list
	var followers []metadata.ClusterNode
	for _, n := range nodes {
		if n.ID != leaderResp.NodeID {
			followers = append(followers, n)
		}
	}

	if len(followers) == 0 {
		// Single node cluster or no active followers
		return nil
	}

	// Shuffle to ensure randomized selection as per security model
	rand.Shuffle(len(followers), func(i, j int) {
		followers[i], followers[j] = followers[j], followers[i]
	})

	// Try up to 2 random followers (as per Theorem 14 "k random followers")
	k := 2
	if len(followers) < k {
		k = len(followers)
	}

	for i := 0; i < k; i++ {
		if err := c.verifyAgainstFollower(ctx, followers[i], leaderResp, st); err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) getRegistryNodes(ctx context.Context) ([]metadata.ClusterNode, error) {
	regDir := c.registryDir
	if regDir == "" {
		return nil, fmt.Errorf("registry not configured")
	}

	path := regDir + "/cluster.json"
	rc, err := c.OpenBlobRead(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("anchored cluster list not found in %s: %w", path, err)
	}
	defer rc.Close()

	var cfg metadata.ClusterConfig
	if err := json.NewDecoder(rc).Decode(&cfg); err != nil {
		return nil, err
	}
	return cfg.Nodes, nil
}

func (c *Client) verifyAgainstFollower(ctx context.Context, node metadata.ClusterNode, leaderResp metadata.TimelineResponse, sessionToken string) error {
	addrStr := node.Address
	if addrStr == "" {
		return nil
	}

	// Parse follower URL
	fURL, err := url.Parse(addrStr)
	if err != nil {
		return fmt.Errorf("invalid follower address %q: %w", addrStr, err)
	}

	// Reconstruct based on leader scheme if missing or inconsistent
	leaderURL, err := url.Parse(c.serverAddr)
	if err == nil {
		if fURL.Scheme == "" {
			fURL.Scheme = leaderURL.Scheme
		}
		if fURL.Host == "" {
			fURL.Host = fURL.Path
			fURL.Path = ""
		}
		// If leader is HTTPS, follower must be HTTPS
		if leaderURL.Scheme == "https" {
			fURL.Scheme = "https"
		}
	}

	maxRetries := 20
	for i := 0; i < maxRetries; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		checkURL := fURL.JoinPath("/v1/timeline")

		req, err := http.NewRequestWithContext(ctx, "GET", checkURL.String(), nil)
		if err != nil {
			return err
		}
		if sessionToken != "" {
			req.Header.Set("Session-Token", sessionToken)
		}

		resp, err := c.httpCli.Do(req)
		if err == nil {
			var followerResp metadata.TimelineResponse
			decodeErr := json.NewDecoder(resp.Body).Decode(&followerResp)
			resp.Body.Close()

			if decodeErr == nil && resp.StatusCode == 200 {
				if followerResp.Index == leaderResp.Index {
					if !bytes.Equal(followerResp.Hash, leaderResp.Hash) {
						return fmt.Errorf("%w: leader hash at index %d does not match follower %s hash", metadata.ErrCryptographicFork, leaderResp.Index, node.ID)
					}
					return nil
				}
				if followerResp.Index > leaderResp.Index {
					// Follower is ahead. The leader might be stale or lying.
					// Re-fetch leader timeline to see if it catches up to this same state.
					var newLeaderResp metadata.TimelineResponse
					_, _, err := c.doRequest(ctx, "GET", "/v1/timeline", nil, requestOptions{skipControl: true, retry: true}, &newLeaderResp)
					if err == nil {
						if newLeaderResp.Index >= followerResp.Index {
							// If they match now, we are good (or we loop and check again)
							leaderResp = newLeaderResp
							continue
						}
					}
				}
			}
		} else if resp != nil {
			resp.Body.Close()
		}

		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("follower %s (%s) failed to synchronize with leader index %d within timeout", node.ID, addrStr, leaderResp.Index)
}
