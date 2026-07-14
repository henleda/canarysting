#!/usr/bin/env nu
# load-images.nu — build local images and load them into the kina `cs` cluster.
#
# CRI name-normalization recipe (see CLAUDE.md / kina fix item):
# manifests reference `docker.io/canarysting/<name>:latest` (containerd's
# CRI-side default-registry normalization). `kina load` (kina >= the
# force-tag fix, kina-cli commit 162962c) now registers the image in the
# k8s.io namespace under that registry-qualified ref itself, force-retagging
# on every load so a rebuilt image never leaves a stale digest behind. Do
# NOT reintroduce a manual `ctr images tag`/export-import bridge here — that
# predates the fix, duplicates work `kina load` already does correctly, and
# is what caused the stale-digest bug (its own tag-exists check skipped
# retagging and masked `kina load`'s pre-fix failure to overwrite).
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
}

# Phase 3 (6-service mesh): tiny east-west service (deploy/m7-window/mesh).
def load-mesh [] {
  print "== building canarysting/mesh:latest =="
  ^container build -t canarysting/mesh:latest -f deploy/m7-window/mesh/Dockerfile .

  print "== loading canarysting/mesh:latest into cluster cs =="
  ^kina load canarysting/mesh:latest --cluster cs
}
