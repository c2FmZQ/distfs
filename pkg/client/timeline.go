package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/c2FmZQ/distfs/pkg/metadata"
)

// VerifyTimeline checks that the Leader's timeline is not isolated by verifying its hash against a Follower node.
// This prevents Split-View/Equivocation attacks.
func (c *Client) VerifyTimeline(ctx context.Context) error {
	var leaderResp metadata.TimelineResponse
	_, _, err := c.doRequest(ctx, "GET", "/v1/timeline", nil, requestOptions{skipControl: true, retry: true}, &leaderResp)
	if err != nil {
		return fmt.Errorf("failed to fetch timeline from leader: %w", err)
	}

	var res struct {
		Nodes []metadata.Node `json:"nodes"`
	}
	_, _, err = c.doRequest(ctx, "GET", "/v1/node", nil, requestOptions{skipControl: true, retry: true}, &res)
	if err != nil {
		return fmt.Errorf("failed to fetch cluster nodes: %w", err)
	}
	nodes := res.Nodes

	c.sessionMu.RLock()
	st := c.sessionToken
	c.sessionMu.RUnlock()

	// Filter and shuffle followers
	var followers []metadata.Node
	for _, n := range nodes {
		if n.ID != leaderResp.NodeID && n.Status == metadata.NodeStatusActive && n.RaftAddress != "" {
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

func (c *Client) verifyAgainstFollower(ctx context.Context, node metadata.Node, leaderResp metadata.TimelineResponse, sessionToken string) error {
	followerAddr := strings.TrimRight(node.Address, "/")
	if followerAddr == "" {
		followerAddr = strings.TrimRight(node.ClusterAddress, "/")
	}
	if followerAddr == "" {
		return nil
	}

	// Ensure correct scheme
	if strings.HasPrefix(c.serverAddr, "https://") && !strings.HasPrefix(followerAddr, "https://") {
		followerAddr = strings.Replace(followerAddr, "http://", "https://", 1)
		if !strings.HasPrefix(followerAddr, "https://") {
			followerAddr = "https://" + followerAddr
		}
	} else if !strings.Contains(followerAddr, "://") {
		if strings.HasPrefix(c.serverAddr, "https://") {
			followerAddr = "https://" + followerAddr
		} else {
			followerAddr = "http://" + followerAddr
		}
	}

	maxRetries := 20
	for i := 0; i < maxRetries; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		req, err := http.NewRequestWithContext(ctx, "GET", followerAddr+"/v1/timeline", nil)
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
						return fmt.Errorf("CRYPTOGRAPHIC FORK DETECTED: leader hash at index %d does not match follower %s hash", leaderResp.Index, node.ID)
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

	return fmt.Errorf("follower %s (%s) failed to synchronize with leader index %d within timeout", node.ID, followerAddr, leaderResp.Index)
}
