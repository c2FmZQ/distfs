# BUGS

# Backend Ports and Advertisement in the Raft Cluster

The backend utilizes three primary ports for its operations:

1.  **Public HTTP Port (`--addr`):** This is the client-facing API port, configurable via the `--addr` flag (defaulting to `:8080`). It's used for all external client communications.
2.  **Internal HTTP Port (Cluster mTLS API - `--cluster-addr`):** This port is dedicated to internal cluster communication, specifically for the mTLS-secured API. It's configured via the `--cluster-addr` flag (defaulting to `:9090`).
3.  **Raft Port (`--raft-bind`):** This port is used for the internal Raft TCP transport layer, handling all Raft-related traffic. It's configured via the `--raft-bind` flag (defaulting to `:8081`).

## Port Advertisement

For effective communication and request forwarding within a Raft cluster, the internal HTTP and Raft ports must be explicitly advertised. This ensures that other nodes can correctly discover and communicate with a specific node, especially in distributed or containerized environments.

Two mandatory flags are used for this purpose when Raft is enabled:

*   **`--cluster-advertise`**: This flag specifies the public `host:port` that other nodes should use to communicate with this node's internal cluster mTLS API. This address is crucial for functionalities such as request forwarding to the leader.
*   **`--raft-advertise`**: This flag specifies the public `host:port` for Raft traffic. This address is used by other nodes for all Raft-related communications, including log replication, leader election, and snapshot transfers.

These advertisement addresses are essential for the cluster's functionality, ensuring that all nodes can correctly discover and communicate with each other, even across different network configurations or when nodes are behind NATs or load balancers.




# The "node key" (specifically, an **Ed25519 private key**, stored as `node.key` in the node's data directory) is a fundamental component of the Raft cluster's security model. It is used in several critical ways to establish identity and secure inter-node communication:

1.  **Unique Node Identity Generation**:
    *   Upon a node's first startup, if it doesn't already exist, a persistent Ed25519 private key (`node.key`) is generated.
    *   The node's unique **Raft Node ID** is then automatically derived from the first 8 bytes of the corresponding Ed25519 **public key** (hex-encoded). This ensures that each node has a cryptographically verifiable and unique identifier within the cluster.

2.  **Mutual TLS (mTLS) for Secure Communication**:
    *   The `node.key` is central to establishing secure communication channels between Raft nodes.
    *   Nodes generate **ephemeral self-signed X.509 certificates**, and these certificates are cryptographically **signed by the node's private `node.key`**.
    *   When two nodes attempt to communicate (e.g., for log replication or leader election), they engage in a mutual TLS (mTLS) handshake. During this process, they exchange their certificates.
    *   A connection is only accepted if the peer's Ed25519 public key (extracted from its presented certificate) is found in the local Raft FSM's list of **authorized public keys (`NodeMeta`)**. This mechanism prevents unauthorized nodes from joining or interacting with the cluster.

3.  **Authorization and Zero-Trust Model**:
    *   By leveraging the `node.key` for mTLS, the cluster enforces a **Zero-Trust security model**. This means that no node is inherently trusted. Instead, each node must cryptographically prove its identity via its `node.key` and be explicitly authorized by the cluster (through the `NodeMeta`) to participate.

In essence, the `node.key` serves as the digital identity card for each Raft node, enabling it to establish trust and secure communications within the distributed system. It's crucial for maintaining the integrity and confidentiality of the cluster's operations.



# In the Raft cluster, **Trust On First Use (TOFU)** is a security mechanism specifically designed to solve the "chicken and egg" problem of establishing initial trust for new nodes joining an existing cluster.

Here's how TOFU is used:

1.  **Initial Trust Problem**: When a new node starts up for the first time and attempts to join a Raft cluster, it has no prior knowledge of which other nodes are legitimate members and, therefore, which public keys to trust for mTLS communication. Without a mechanism to establish this initial trust, it would be unable to connect securely.

2.  **TOFU Mode Activation**: A node enters "TOFU Mode" under specific conditions:
    *   It is "fresh," meaning its internal `initialized` status is `false` (it has never successfully joined or been part of a cluster before).
    *   It is *not* the designated bootstrap leader (the very first node used to initialize a brand new cluster).

3.  **Behavior in TOFU Mode**: While in TOFU Mode, the node temporarily relaxes its strict enforcement of the authorized key list. It will accept a connection from an **unknown peer**, which is expected to be the existing **Leader** of the cluster. This temporary acceptance is crucial because it allows the new node to:
    *   Successfully establish an initial connection with the leader.
    *   Receive the complete and authoritative cluster state, including the `NodeMeta` which contains the list of all **trusted and authorized public keys** of the cluster members.

4.  **Transition to Strict Mode**: As soon as the new node successfully receives this vital metadata from another node (the Leader), its `initialized` status changes to `true`. From this point forward, the node exits TOFU Mode and permanently transitions to **Strict Mode**. In Strict Mode, it will then **strictly enforce the authorized key list for all subsequent connections**, even after restarts. Any future connection attempts from unknown or unauthorized peers will be rejected.

In essence, TOFU acts as a secure, one-time bootstrapping mechanism. It allows uninitialized nodes to safely acquire the necessary trust anchors (authorized public keys) from a trusted leader, enabling them to integrate into a Zero-Trust cluster without compromising security in subsequent interactions.



# The `/api/cluster` page functions as the **Cluster Manager Dashboard**, providing tools for monitoring and managing the Raft consensus cluster.

### What it Does

The Cluster Manager Dashboard offers the following key functionalities:

1.  **Authentication**: Before accessing any cluster information or management features, the user must provide a "Raft Secret." This secret acts as a password to authorize access to these sensitive cluster operations.
2.  **Cluster Status Overview**: Once authenticated, the dashboard displays real-time information about the Raft cluster, including:
    *   The ID of the local node.
    *   The current state of the node (e.g., Leader, Follower).
    *   The ID and network address of the current cluster leader.
    *   A table listing all nodes in the cluster, showing their unique Node ID, advertised Raft and Cluster API addresses, their role (Leader/Follower/Non-Voter), and version information (application, protocol, schema).
3.  **Node Management**:
    *   **Add Node**: Provides a form to join a new node to the cluster. This requires specifying the new node's Cluster Address (HTTP address) and its Public Key (Base64 encoded). If the Public Key is left blank, the leader establishes a TLS connection to the Cluster Address and extracts the node's Public Key from the its TLS Certificate. There's an option to add the node as a non-voter. When a node is joined, the leader automatically discovers its full configuration via /api/cluster/status.
    *   **Remove Node**: Allows an authenticated user to remove an existing node from the cluster. This is a destructive operation, and confirmation is typically required.
4.  **Refresh**: A refresh button is available to fetch and update the latest cluster status.

### Usage

The page is an interactive interface primarily for system administrators or operators responsible for maintaining the cluster. It allows for:
*   Gaining insight into the operational state of the distributed system.
*   Scaling the cluster by adding new nodes.
*   Maintaining cluster health by removing failed or decommissioned nodes.

### Access Control

Access to the `/api/cluster` page and its associated API endpoints (e.g., `/api/cluster/join`, `/api/cluster/status`, `/api/cluster/remove`) is protected by a **Raft Secret**.

*   **Raft Secret**: This is a mandatory, shared secret configured via the `--raft-secret` flag when the server is started with Raft enabled. All cluster management endpoints strictly enforce the presence and correctness of this secret.
*   **Authentication Mechanism**: Unlike the typical team-centric, JWT-based authentication used for game and team data (which relies on `AccessAdmin` roles), access to `/api/cluster` is solely dependent on possessing this `Raft Secret`. It acts as a direct authentication token for cluster-level administrative operations.
*   **Security**: The server will fail to start if the `--raft-secret` is not provided when Raft is enabled. This ensures that only operators with knowledge of this secret can perform sensitive cluster management tasks, providing a distinct layer of security for the Raft infrastructure itself.

In summary, the `/api/cluster` page is a powerful operational tool for managing the Raft cluster, secured by a dedicated `Raft Secret` to ensure that only authorized personnel can make changes to the cluster's topology and view its internal state.



