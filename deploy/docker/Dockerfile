# Partout server container image.
# Build from the repo root:
#   docker build -f deploy/docker/Dockerfile -t partout:local .
# Pure-Go build (modernc.org/sqlite) — no CGO, so the runtime image needs
# nothing but ca-certificates/wget and a non-root user.

FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/blawesom/partout/internal/agent/facts.Version=${VERSION}" \
    -o /out/partout ./cmd/partout

FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /var/lib/partout --shell /usr/sbin/nologin partout
COPY --from=build /out/partout /usr/local/bin/partout
RUN mkdir -p /var/lib/partout && chown partout:partout /var/lib/partout
VOLUME /var/lib/partout
USER partout
EXPOSE 8443
ENTRYPOINT ["partout", "--mode=server", "--db=/var/lib/partout/partout.db"]
