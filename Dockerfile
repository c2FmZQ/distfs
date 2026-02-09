# Copyright 2026 TTBT Enterprises LLC
FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /bin/storage-node ./cmd/storage-node
RUN go build -o /bin/distfs ./cmd/distfs

FROM alpine:latest
COPY --from=builder /bin/storage-node /bin/storage-node
COPY --from=builder /bin/distfs /bin/distfs
COPY scripts/test-e2e.sh /bin/test-e2e.sh
RUN chmod +x /bin/test-e2e.sh

ENTRYPOINT ["/bin/storage-node"]
