# Whispera Microservice Architecture Blueprint

## Goals
- Preserve existing client + server behaviour while decomposing into deployable services.
- Enable independent scaling, deployment, and failure isolation.
- Reuse current domain packages (`internal/...`) as service libraries with minimal refactoring.

## Target Services

### 1. Edge Gateway
- **Protocols:** UDP Noise, TCP/TLS, WS/WS2.
- **Responsibilities:** Accept inbound connections, forward session requests to Auth Service, route encrypted payloads to Data Plane Service.
- **Dependencies:** `internal/handshake`, `internal/proto`, `internal/server` (light wrapper).
- **Interfaces:** `AuthService.SessionOpen`, `DataPlaneService.OpenTransport`.

### 2. Auth & Session Service
- **Responsibilities:** Token validation, Noise/TLS handshake orchestration, AEAD/session issuance, session lifecycle.
- **Dependencies:** `internal/handshake`, `internal/server.SessionManager`, `internal/crypto`.
- **Storage:** Redis (sessions), Postgres (tokens), Vault (keys).
- **Interfaces:** gRPC: `SessionOpen`, `SessionRefresh`, streaming `SessionEvents`.

### 3. Data Plane Service
- **Responsibilities:** Stream multiplexing, AEAD encryption/decryption, TUN/TAP handling, NAT traversal helpers.
- **Dependencies:** `cmd/client/dataplane*`, `internal/tunstack`, `internal/client/transport`, `internal/proto`.
- **Interfaces:** Bidirectional QUIC streams (`Edge` ↔ `DataPlane`), gRPC control plane (`AttachSession`, `DetachSession`, `Stats`).

### 4. Obfuscation & ML Service
- **Responsibilities:** ML-driven protocol selection, behavioural mimicry, DPI circumvention logic.
- **Dependencies:** `internal/obfuscation`, `ml_engine`.
- **Interfaces:** gRPC: `SelectProfile`, `ReportTelemetry`, async pub/sub for model updates.

### 5. Policy & Config Service
- **Responsibilities:** Central configuration, split-tunnel rules, app profiles.
- **Dependencies:** `internal/config`, `internal/client/configuri`.
- **Interfaces:** REST/gRPC: `GetClientConfig`, `StreamConfigUpdates`.

### 6. Monitoring & Metrics Service
- **Responsibilities:** Collect Prometheus metrics, adaptive monitoring, performance optimisation triggers.
- **Dependencies:** `internal/metrics`, `internal/monitoring`, `internal/optimization`.
- **Interfaces:** Prometheus scrape endpoint, gRPC `ReportMetric`.

### 7. DNS & Proxy Service
- **Responsibilities:** DNS proxying and SOCKS5/HTTP proxy management.
- **Dependencies:** `internal/dns`, `cmd/client/proxy`.
- **Interfaces:** gRPC `OpenDNSStream`, `OpenProxySession`.

### 8. P2P Discovery Service
- **Responsibilities:** Bootstrapping, peer discovery, secure message relay.
- **Dependencies:** `internal/p2p`.
- **Interfaces:** gRPC `Join`, `Publish`, `Subscribe`.

## Shared Infrastructure
- **Service Mesh:** Istio/Linkerd for mTLS, routing, retries.
- **Service Discovery:** Consul or mesh-native discovery.
- **Messaging:** NATS/Kafka for telemetry, config invalidation.
- **Secrets:** HashiCorp Vault or cloud equivalent.
- **Tracing:** OpenTelemetry instrumentation, Jaeger backend.

## Migration Strategy
1. **Abstract Contracts:** Define protobuf/IDL under `api/proto` for all service interactions. Keep shims compatible with existing in-process functions.
2. **Library Extraction:** Wrap existing logic into cohesive packages implementing service interfaces (e.g., `internal/services/auth`).
3. **Service Skeletons:** Create new binaries in `cmd/services/*`, each exposing gRPC/HTTP endpoints but reusing existing packages.
4. **Sidecar Mode:** Initially run new services side-by-side with monolith, routing only specific flows to them (strangler pattern).
5. **Data Stores:** Introduce dedicated storage per service. Start with in-memory adapters for parity, swap to durable backends later.
6. **Observability:** Add metrics/tracing hooks before switching traffic to detect regressions.
7. **Cut-over:** Gradually flip feature flags or routing rules to point clients to microservices.
8. **Decommission Monolith:** Once parity verified, retire legacy entrypoints (`cmd/client/main.go`, `cmd/server/main.go`).

## Current Sprint Focus
- Finalise protobuf contracts for Auth, DataPlane, Policy services.
- Scaffold gRPC servers/clients (`cmd/services/authsvc`, `cmd/services/dataplanesvc`, `internal/clients/authclient`).
- Provide adapters to keep existing binaries operational during migration.

## Non-Goals
- Frontend (`client-package-tauri`) changes.
- Alteration of network protocol semantics or client UX.
- Immediate introduction of third-party dependencies beyond gRPC/OpenTelemetry baseline.


