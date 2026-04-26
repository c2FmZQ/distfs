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

// VerifyTimeline performs a "Deep Audit" of the cluster's linear history.
// It executes a metadata operation (equivalent to 'stat /') with 100% sampling,
// forcing the client to verify the signed response receipt against a random follower node.
// This prevents Split-View/Equivocation attacks with cryptographic certainty.
func (c *Client) VerifyTimeline(ctx context.Context) error {
	// 1. Configure client for 100% sampling for this specific operation
	cauditor := c.WithTimelineSampleRate(1.0)

	// 2. Perform an authenticated metadata operation (Stat on root)
	// This will trigger unsealResponse -> VerifyTimelineReceipt internally.
	_, err := cauditor.Stat(ctx, "/")
	if err != nil {
		return fmt.Errorf("deep audit failed: %w", err)
	}

	return nil
}

// VerifyTimelineWithNodes performs the timeline verification against a specific list of nodes.
// DEPRECATED: Use VerifyTimeline or VerifyTimelineReceipt with anchored nodes.
func (c *Client) VerifyTimelineWithNodes(ctx context.Context, nodes []metadata.ClusterNode) error {
	// This was the old "Hedged Reads" logic. Since we now use Response Binding,
	// we just perform a VerifyTimeline check which uses the anchored registry list.
	return c.VerifyTimeline(ctx)
}

func (c *Client) getRegistryNodes(ctx context.Context) ([]metadata.ClusterNode, error) {
	regDir := c.registryDir
	if regDir == "" {
		return nil, fmt.Errorf("registry not configured")
	}

	// 1. Check Cache
	c.anchoredNodesMu.RLock()
	if len(c.anchoredNodes) > 0 {
		nodes := c.anchoredNodes
		c.anchoredNodesMu.RUnlock()
		return nodes, nil
	}
	c.anchoredNodesMu.RUnlock()

	// 2. Fetch from Registry (with sampling disabled to prevent recursion)
	cauditor := c.WithTimelineSampleRate(0)
	path := regDir + "/cluster.json"
	rc, err := cauditor.OpenBlobRead(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("anchored cluster list not found in %s: %w", path, err)
	}
	defer rc.Close()

	var cfg metadata.ClusterConfig
	if err := json.NewDecoder(rc).Decode(&cfg); err != nil {
		return nil, err
	}

	// 3. Update Cache
	c.anchoredNodesMu.Lock()
	c.anchoredNodes = cfg.Nodes
	c.anchoredNodesMu.Unlock()

	return cfg.Nodes, nil
}
