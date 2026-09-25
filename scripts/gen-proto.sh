#!/usr/bin/env bash
# Regenerate the Go protobuf/gRPC bindings from proto/partout/partout.proto.
#
# The generator versions must match the ones recorded in the checked-in
# header (protoc-gen-go v1.36.12, protoc v3.21.12) so regeneration produces a
# minimal diff. protoc-gen-go / protoc-gen-go-grpc live in $GOBIN.
set -euo pipefail

cd "$(dirname "$0")/.."

export PATH="${GOBIN:-$HOME/go/bin}:/usr/local/go/bin:$PATH"

out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

protoc -I proto \
  --go_out="$out" --go_opt=paths=source_relative \
  --go-grpc_out="$out" --go-grpc_opt=paths=source_relative \
  proto/partout/partout.proto

cp "$out/partout/partout.pb.go" "$out/partout/partout_grpc.pb.go" internal/proto/
echo "regenerated internal/proto/partout{,_grpc}.pb.go"
