FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/whispera ./app/server \
 && CGO_ENABLED=0 go build -o /out/whispera-go-client ./app/goclient \
 && CGO_ENABLED=0 go build -o /out/censor ./scripts/e2e/censor

FROM alpine:3.20
RUN apk add --no-cache curl tcpdump ca-certificates
COPY --from=build /out/whispera /app/whispera
COPY --from=build /out/whispera-go-client /app/whispera-go-client
COPY --from=build /out/censor /app/censor
COPY scripts/e2e/client-run.sh /app/client-run.sh
RUN chmod +x /app/client-run.sh
WORKDIR /app
