# deploy/

Deployment manifests and examples. Empty for now.

Expected contents as the project matures: Kubernetes manifests for the engine,
Envoy filter configuration wiring the adapter, an nginx/OpenResty example, and
the privileges the eBPF loader needs (it programs kernel maps, so it requires
appropriate capabilities). See docs/ADAPTERS.md and docs/IDENTITY.md.
