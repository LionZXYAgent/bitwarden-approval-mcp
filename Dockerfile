# syntax=docker/dockerfile:1

# ---- build stage ----
FROM golang:1.26-alpine AS build
WORKDIR /src
# Cache modules first.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
# Fully static, stripped binary. CGO is off so it runs on bare Alpine/musl.
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/bwgate ./cmd/bwgate

# ---- runtime stage ----
FROM alpine:3.22
# ca-certificates: needed for TLS to the Bitwarden and Telegram APIs.
# tzdata: so TZ-aware timestamps in the approval prompt are correct.
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S bwgate && adduser -S -G bwgate -H -s /sbin/nologin bwgate
COPY --from=build /out/bwgate /usr/local/bin/bwgate
USER bwgate
# Localhost by default; override BWGATE_ADDR to 0.0.0.0:8099 to expose.
ENV BWGATE_ADDR=0.0.0.0:8099
EXPOSE 8099
ENTRYPOINT ["/usr/local/bin/bwgate"]
