FROM golang:1.25-alpine AS builder-server

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /whispera-server ./cmd/server


FROM node:20-alpine AS builder-panel

WORKDIR /src/panel
COPY panel/package.json panel/package-lock.json ./
RUN npm ci --include=dev --force

COPY panel/ .
RUN npx nest build


FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /opt/whispera

COPY --from=builder-server /whispera-server /usr/local/bin/whispera
COPY --from=builder-panel /src/panel/dist ./panel/dist
COPY --from=builder-panel /src/panel/public ./panel/public
COPY --from=builder-panel /src/panel/package.json ./panel/package.json
COPY --from=builder-panel /src/panel/package-lock.json ./panel/package-lock.json
COPY --from=builder-panel /src/panel/nest-cli.json ./panel/nest-cli.json

RUN apk add --no-cache nodejs npm \
    && cd panel && npm ci --omit=dev --force && apk del npm

COPY panel/.env.example ./panel/.env

RUN mkdir -p /etc/whispera /var/log/whispera

EXPOSE 8443/tcp 8443/udp 8080 3000

ENTRYPOINT ["/usr/local/bin/whispera"]
CMD ["-config", "/etc/whispera/config.yaml", "-api", ":8080"]
