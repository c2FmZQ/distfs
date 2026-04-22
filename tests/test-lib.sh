
# Function to wait for cluster readiness
wait_for_ready() {
    echo "Waiting for cluster leader..."
    for i in $(seq 1 30); do
        if wget -qO- "http://storage-node-1:8080/v1/health" 2>/dev/null | grep -q '"is_leader":true'; then
            echo "Cluster leader found."
            
            # Also wait for OIDC discovery
            echo "Waiting for OIDC discovery..."
            for j in $(seq 1 30); do
                if wget -qO- "http://storage-node-1:8080/v1/auth/config" 2>/dev/null | grep -q "issuer"; then
                    echo "OIDC discovery successful."
                    return 0
                fi
                sleep 1
            done
            echo "Timed out waiting for OIDC discovery."
            return 1
        fi
        sleep 1
    done
    echo "Timed out waiting for cluster leader."
    return 1
}

global_setup() {
    # GLOBAL SETUP: Create Admin
    echo "PERFORMING GLOBAL SETUP..."
    local JWT=$(wget -qO- "http://test-auth:8080/mint?email=admin@example.com")
    if ! distfs --disable-doh --allow-insecure --use-pinentry=false --config "$1/config.json" init --new --server http://storage-node-1:8080 --jwt "$JWT"; then
        echo "GLOBAL SETUP FAILED: Admin initialization failed"
        exit 1
    fi

    ADMIN_ID=$(distfs --disable-doh --allow-insecure --use-pinentry=false --config "$1/config.json" whoami)
    echo "Global Admin ID: $ADMIN_ID"

    echo "Initializing canonical root and system backbone..."
    if ! distfs --disable-doh --allow-insecure --use-pinentry=false --config "$1/config.json" admin-create-root; then
        echo "GLOBAL SETUP FAILED: admin-create-root failed"
        exit 1
    fi
}

provision_user() {
    local name=$1
    local email=$2
    local conf="/tmp/${name}-config.json"
    local path="/users/${name}"
    echo "Provisioning ${name} ($email) at ${path}..."
    
    local U_JWT=$(wget -qO- "http://test-auth:8080/mint?email=$email")
    local U_OUT=$(distfs --disable-doh --allow-insecure --use-pinentry=false --config "$conf" init --new --server http://storage-node-1:8080 --jwt "$U_JWT")
    local U_ID=$(echo "$U_OUT" | grep "User ID:" | cut -d: -f2 | tr -d ' ')
    
    # Provision directory and unlock via Global Admin
    distfs --disable-doh --allow-insecure --use-pinentry=false --admin --config "$DISTFS_CONFIG_DIR/config.json" registry-add --yes --unlock --quota 100000000,5000 --home "$name" "$U_ID"
    
    # Add to users group to allow traversal
    distfs --disable-doh --allow-insecure --use-pinentry=false --admin --config "$DISTFS_CONFIG_DIR/config.json" group-add "users" "$name"
}
