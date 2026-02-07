# BUGS

* The metadata backend MUST know the structure of the filesystem to control access, garbage collection, etc
  * It MUST know the content of each directory
  * It MUST know which chunks belong to which files
  * It MUST know the permissions on each file and directory
  * It MUST know the member IDs of each group (not the UserIDs, not the group names)
  * it MUST NOT know the file names or directory names (except the root / directory?). These are encrypted with the directory key

* The data backend MUST enforce permissions on chunks.
  * Only clients with READ access to a file/directory can READ a chunk that belongs to that file/directory
  * Only clients with WRITE access to a file/directory can WRITE a chunk that belongs to that file/directory

* Cluster management needs to follow model of skorekeeper
  * Node keys for TLS
  * /api/cluster management screen
  * Allow nodes to be Voter or NonVoter
  * forward metadata requests to cluster leader

* Encryption key for logs MUST be rotated
  * We should rotate the key used to encrypt raft data after every snapshot.
