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
      load-mesh
    } else if $image == "dashboard-web" {
      load-dashboard-web
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

# Phase 4 (dashboard): frontend (dashboard/app, Next.js standalone build).
# Context is dashboard/app, not the repo root — the standalone build only
# needs its own package.json/lockfile, unlike Dockerfile.core which COPYs the
# whole repo for the go:embed bpf .o files.
def load-dashboard-web [] {
  print "== building canarysting/dashboard-web:latest =="
  ^container build -t canarysting/dashboard-web:latest -f deploy/kina/Dockerfile.dashboard-web dashboard/app

  print "== loading canarysting/dashboard-web:latest into cluster cs =="
  ^kina load canarysting/dashboard-web:latest --cluster cs

  let already_tagged = (
    ^container exec cs-control-plane ctr -n k8s.io images ls
    | complete
    | get stdout
    | str contains "docker.io/canarysting/dashboard-web:latest"
  )

  if $already_tagged {
    print "== docker.io/canarysting/dashboard-web:latest already tagged, skipping retag =="
  } else {
    print "== retagging as docker.io/canarysting/dashboard-web:latest =="
    ^container exec cs-control-plane ctr -n k8s.io images tag canarysting/dashboard-web:latest docker.io/canarysting/dashboard-web:latest
  }
}

# Phase 3 (6-service mesh): tiny east-west service (deploy/m7-window/mesh),
# same retag dance as load-core. `ctr images tag` needs the source image in
# the k8s.io namespace; `kina load` lands it in `default`, so bridge via
# export/import first (see module docstring).
def load-mesh [] {
  print "== building canarysting/mesh:latest =="
  ^container build -t canarysting/mesh:latest -f deploy/m7-window/mesh/Dockerfile .

  print "== loading canarysting/mesh:latest into cluster cs =="
  ^kina load canarysting/mesh:latest --cluster cs

  let already_tagged = (
    ^container exec cs-control-plane ctr -n k8s.io images ls
    | complete
    | get stdout
    | str contains "docker.io/canarysting/mesh:latest"
  )

  if $already_tagged {
    print "== docker.io/canarysting/mesh:latest already tagged, skipping retag =="
  } else {
    print "== bridging canarysting/mesh:latest into the k8s.io namespace =="
    ^container exec cs-control-plane ctr -n default images export /tmp/canarysting-mesh.tar canarysting/mesh:latest
    ^container exec cs-control-plane ctr -n k8s.io images import /tmp/canarysting-mesh.tar
    print "== retagging as docker.io/canarysting/mesh:latest =="
    ^container exec cs-control-plane ctr -n k8s.io images tag canarysting/mesh:latest docker.io/canarysting/mesh:latest
  }
}
