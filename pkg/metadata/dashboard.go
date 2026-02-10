// Copyright 2026 TTBT Enterprises LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metadata

import (
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

func (s *Server) handleClusterDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/api/cluster" {
		s.serveDashboardHTML(w, r)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/cluster/status" {
		s.handleClusterStatus(w, r) // Reuse existing handler logic?
		// handleClusterStatus uses v1 response format. Maybe ok.
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/cluster/join" {
		s.handleClusterJoin(w, r) // Reuse existing
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/cluster/remove" {
		s.handleClusterRemove(w, r)
		return
	}
	
	http.NotFound(w, r)
}

func (s *Server) handleClusterRemove(w http.ResponseWriter, r *http.Request) {
	if s.raft.State() != raft.Leader {
		http.Error(w, "not leader", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	f := s.raft.RemoveServer(raft.ServerID(req.ID), 0, 0)
	if err := f.Error(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) serveDashboardHTML(w http.ResponseWriter, r *http.Request) {
	stats := s.raft.Stats()
	data := struct {
		NodeID      string
		State       string
		Leader      string
		Nodes       []Node
		SecretParam string
	}{
		NodeID:      stats["id"],
		State:       s.raft.State().String(),
		Leader:      string(s.raft.Leader()),
		SecretParam: "?secret=" + r.URL.Query().Get("secret"),
	}

	// Fetch Nodes from FSM
	s.fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var n Node
			if err := json.Unmarshal(v, &n); err == nil {
				data.Nodes = append(data.Nodes, n)
			}
		}
		return nil
	})

	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <title>DistFS Cluster Manager</title>
    <style>
        body { font-family: sans-serif; padding: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .form-group { margin-bottom: 10px; }
        label { display: block; margin-bottom: 5px; }
        input { padding: 5px; width: 300px; }
        button { padding: 5px 10px; }
    </style>
</head>
<body>
    <h1>DistFS Cluster Manager</h1>
    
    <h3>Local Node: {{.NodeID}} ({{.State}})</h3>
    <h3>Leader: {{.Leader}}</h3>

    <h2>Nodes</h2>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Public Address</th>
                <th>Raft Address</th>
                <th>Status</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            {{range .Nodes}}
            <tr>
                <td>{{.ID}}</td>
                <td>{{.Address}}</td>
                <td>{{.RaftAddress}}</td>
                <td>{{.Status}}</td>
                <td>
                    <button onclick="removeNode('{{.ID}}')">Remove</button>
                </td>
            </tr>
            {{end}}
        </tbody>
    </table>

    <h2>Add Node</h2>
    <div class="form-group">
        <label>Node ID</label>
        <input type="text" id="joinID" placeholder="node-id">
    </div>
    <div class="form-group">
        <label>Raft Address</label>
        <input type="text" id="joinAddr" placeholder="127.0.0.1:8081">
    </div>
    <button onclick="joinNode()">Join Node</button>

    <script>
        const secret = "{{.SecretParam}}";
        const secretVal = new URLSearchParams(window.location.search).get("secret");

        async function apiCall(url, method, body) {
            const headers = {"Content-Type": "application/json"};
            if (secretVal) headers["X-Raft-Secret"] = secretVal;
            
            const resp = await fetch(url + secret, {
                method: method,
                headers: headers,
                body: JSON.stringify(body)
            });
            if (!resp.ok) {
                alert("Error: " + await resp.text());
            } else {
                window.location.reload();
            }
        }

        function joinNode() {
            const id = document.getElementById("joinID").value;
            const addr = document.getElementById("joinAddr").value;
            apiCall("/api/cluster/join", "POST", {id: id, address: addr});
        }

        function removeNode(id) {
            if (confirm("Are you sure you want to remove " + id + "?")) {
                apiCall("/api/cluster/remove", "POST", {id: id});
            }
        }
    </script>
</body>
</html>
`
	t, err := template.New("dashboard").Parse(tmpl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t.Execute(w, data)
}
