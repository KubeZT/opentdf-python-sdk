# Go interoperability driver

This driver uses the upstream OpenTDF Go SDK v0.35.0. Use the
[local KAS setup](../java/local-kas.md) and the same environment variables
as the [Java driver](../java/README.md). Use Go 1.26.10.

```sh
CGO_ENABLED=0 go build -mod=readonly -o go-driver .
./go-driver create input.bin from-go.tdf
./go-driver open from-go.tdf recovered.bin
cmp input.bin recovered.bin
unzip -Z1 from-go.tdf
```

The pinned SDK writes the Java-compatible entry name `0.manifest.json`.
Its reader also accepts the spec entry name `manifest.json`. Use `open`
with a spec archive produced by either native SDK to check that direction.
