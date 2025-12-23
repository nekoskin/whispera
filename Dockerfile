# Multi-stage production-ready build for Whispera
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata gcc musl-dev

# Create user
RUN adduser -D -s /bin/sh whispera

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build all components with production optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=${VERSION:-dev} -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -a -installsuffix cgo -o whispera-server ./cmd/server

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=${VERSION:-dev} -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -a -installsuffix cgo -o whispera-client ./cmd/client

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=${VERSION:-dev} -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -a -installsuffix cgo -o whispera-speedtest-server ./cmd/speedtest

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=${VERSION:-dev} -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -a -installsuffix cgo -o whispera-keygen ./cmd/keygen

# Production stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk --no-cache add \
    ca-certificates \
    tzdata \
    iptables \
    iproute2 \
    curl \
    bash \
    && rm -rf /var/cache/apk/*

# Create non-root user for security
RUN adduser -D -s /bin/sh whispera

# Create necessary directories
RUN mkdir -p /etc/whispera /var/log/whispera /var/lib/whispera /app && \
    chown -R whispera:whispera /etc/whispera /var/log/whispera /var/lib/whispera /app

# Copy binaries from builder
COPY --from=builder /app/whispera-server /app/whispera-server
COPY --from=builder /app/whispera-client /app/whispera-client
COPY --from=builder /app/whispera-speedtest-server /app/whispera-speedtest-server
COPY --from=builder /app/whispera-keygen /app/whispera-keygen

# Copy configuration
COPY --from=builder /app/packaging/ /etc/whispera/

# Set proper permissions
RUN chmod +x /app/whispera-* && \
    chown -R whispera:whispera /app

# Switch to non-root user
USER whispera

# Set working directory
WORKDIR /app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose ports
EXPOSE 51820/udp 4443/tcp 8443/tcp 9101/tcp 8080/tcp

# Default command
CMD ["./whispera-server"]
