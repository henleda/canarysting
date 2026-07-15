#!/usr/bin/env nu
# load-images.nu — build local images and load them into the kina `cs` cluster.
#
# CRI name-normalization recipe (see CLAUDE.md / kina fix item):
# manifests reference `docker.io/canarysting/<name>:latest` (containerd's
# CRI-side default-registry normalization). `kina load` lands the image in
# containerd's `default` namespace under the bare tag; kubelet/CRI reads from
# the `k8s.io` namespace, so a bridge is required. kina-cli commit 162962c
# fixed `kina load` to do this bridge + force-retag itself — but that fix is
# only in a cargo-built kina, not yet in a tagged kina release. `eval "$(mise
# env)"` puts mise's RELEASED kina (0.2.0, 2026-07-10, predates 162962c) on
# PATH ahead of any cargo-built fixed binary, so under the normal dev
# environment `kina load` silently leaves the image stranded in `default` —
# the cluster keeps serving whatever stale digest was last in `k8s.io`
# (confirmed: P2 deploy, 2026-07-15 — kina reported "loaded successfully"
# three times, including under a brand-new tag, and none of it reached
# `k8s.io`). So the bridge below is unconditional (no presence-skip; that
# skip is what masked the pre-162962c bug the first time around) and
# version-independent — it works whether or not the PATH's kina has the fix.
# Drop it again ONLY once kina 162962c ships a release and that release is
# pinned in mise (see github follow-up: release kina load fix so mise-pinned
# kina has it).
#
# --no-cache on every `container build` below: Apple Container's build cache
# has reused a stale layer across a source change without any error (a
# rebuild that looks successful but ships old code — the same "reported
# success, stale artifact" shape as the bridge bug above). Unconditional
# --no-cache trades a slower rebuild for a rebuild that's actually correct.
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

# bridge-to-k8s-io moves image:latest from containerd's `default` namespace
# (where `kina load` lands it) into `k8s.io` (where kubelet/CRI reads from),
# force-retagging so a rollout restart always picks up the fresh digest. See
# the module docstring for why this is unconditional and version-independent.
def bridge-to-k8s-io [image: string] {
  let safe = ($image | str replace "/" "-")
  let tar = $"/tmp/($safe).tar"
  print $"== bridging ($image):latest into the k8s.io namespace =="
  ^container exec cs-control-plane ctr -n default images export $tar $"($image):latest"
  ^container exec cs-control-plane ctr -n k8s.io images import $tar
  ^container exec cs-control-plane ctr -n k8s.io images tag --force $"($image):latest" $"docker.io/($image):latest"
}

def load-core [] {
  print "== building canarysting/core:latest =="
  ^container build --no-cache -t canarysting/core:latest -f deploy/kina/Dockerfile.core .

  print "== loading canarysting/core:latest into cluster cs =="
  ^kina load canarysting/core:latest --cluster cs
  bridge-to-k8s-io "canarysting/core"
}

# Phase 4 (dashboard): frontend (dashboard/app, Next.js standalone build).
# Context is dashboard/app, not the repo root — the standalone build only
# needs its own package.json/lockfile, unlike Dockerfile.core which COPYs the
# whole repo for the go:embed bpf .o files.
def load-dashboard-web [] {
  print "== building canarysting/dashboard-web:latest =="
  ^container build --no-cache -t canarysting/dashboard-web:latest -f deploy/kina/Dockerfile.dashboard-web dashboard/app

  print "== loading canarysting/dashboard-web:latest into cluster cs =="
  ^kina load canarysting/dashboard-web:latest --cluster cs
  bridge-to-k8s-io "canarysting/dashboard-web"
}

# Phase 3 (6-service mesh): tiny east-west service (deploy/m7-window/mesh).
def load-mesh [] {
  print "== building canarysting/mesh:latest =="
  ^container build --no-cache -t canarysting/mesh:latest -f deploy/m7-window/mesh/Dockerfile .

  print "== loading canarysting/mesh:latest into cluster cs =="
  ^kina load canarysting/mesh:latest --cluster cs
  bridge-to-k8s-io "canarysting/mesh"
}
