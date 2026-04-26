package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

	c.sessionMu.RLock()
	st := c.sessionToken
	c.sessionMu.RUnlock()

	var followerAddr string
	baseL := strings.TrimRight(c.serverAddr, "/")
	for _, u := range leaderResp.ClusterURLs {
		cleanU := strings.TrimRight(u, "/")
		if !strings.Contains(cleanU, "://") {
			if strings.HasPrefix(baseL, "https://") {
				cleanU = "https://" + cleanU
			} else {
				cleanU = "http://" + cleanU
			}
		}

		if cleanU != baseL {
			followerAddr = cleanU
			break
		}
	}
	if followerAddr == "" {
		// Single node cluster, vacuously true
		return nil
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
		if st != "" {
			req.Header.Set("Session-Token", st)
		}

		resp, err := c.httpCli.Do(req)
		if err == nil {
			var followerResp metadata.TimelineResponse
			decodeErr := json.NewDecoder(resp.Body).Decode(&followerResp)
			resp.Body.Close()
			if decodeErr == nil && resp.StatusCode == 200 {
				if followerResp.Index >= leaderResp.Index {
					if followerResp.Index == leaderResp.Index && !bytes.Equal(followerResp.Hash, leaderResp.Hash) {
						return fmt.Errorf("CRYPTOGRAPHIC FORK DETECTED: leader hash at index %d does not match follower hash", leaderResp.Index)
					}
					return nil
				}
			}
		} else if resp != nil {
			resp.Body.Close()
		}

		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("follower %s failed to catch up to leader index %d within timeout", followerAddr, leaderResp.Index)
}
