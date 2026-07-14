#!/usr/bin/env nu
# load-images.nu — build local images and load them into the kina `cs` cluster.
#
# CRI name-normalization recipe (mandatory, see CLAUDE.md / kina fix item):
# `kina load` imports under the bare tag, but manifests reference
# `docker.io/canarysting/core:latest` (containerd's CRI-side default-registry
# normalization). After loading, retag inside the control-plane node's
# containerd namespace so the in-cluster image reference resolves.
#
# Usage:
#   nu deploy/kina/load-images.nu
#   nu deploy/kina/load-images.nu --images [core]

def main [--images: list<string> = [core]] {
  for image in $images {
    if $image == "core" {
      load-core
    } else if $image == "mesh" {
      # Phase 3 (6-service mesh): not built yet. Left as a placeholder so the
      # --images flag has a documented extension point when that work lands.
      print $"skipping ($image): mesh image not implemented until Phase 3"
    } else {
      print $"skipping unknown image: ($image)"
    }
  }
}

def load-core [] {
  print "== building canarysting/core:latest =="
  ^container build -t canarysting/core:latest -f deploy/kina/Dockerfile.core .

  print "== loading canarysting/core:latest into cluster cs =="
  ^kina load canarysting/core:latest --cluster cs

  let already_tagged = (
    ^container exec cs-control-plane ctr -n k8s.io images ls
    | complete
    | get stdout
    | str contains "docker.io/canarysting/core:latest"
  )

  if $already_tagged {
    print "== docker.io/canarysting/core:latest already tagged, skipping retag =="
  } else {
    print "== retagging as docker.io/canarysting/core:latest =="
    ^container exec cs-control-plane ctr -n k8s.io images tag canarysting/core:latest docker.io/canarysting/core:latest
  }
}
