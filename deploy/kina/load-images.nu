#!/usr/bin/env nu
# load-images.nu — build local images and load them into the kina `cs` cluster.
#
# CRI name-normalization recipe (see CLAUDE.md / kina fix item):
# manifests reference `docker.io/canarysting/<name>:latest` (containerd's
# CRI-side default-registry normalization). kubelet/CRI reads images from
# containerd's `k8s.io` namespace under that exact registry-qualified ref,
# so a bridge from wherever `kina load` actually lands the image is
# required.
#
# Stale-digest defeat (confirmed live, P2 deploy 2026-07-15): `kina load`
# (mise-pinned kina 0.2.0, predates commit 162962c) imports into
# containerd's `default` namespace under whatever tag the caller passed,
# and `ctr images import` does NOT overwrite an existing tag pointing at an
# old digest — it silently leaves the existing name→digest mapping alone.
# So `kina load canarysting/core:latest` on a second (or Nth) run left
# `latest` pointing at the FIRST digest ever loaded no matter how many
# times the image was rebuilt; every step reported "loaded successfully"
# while the cluster kept serving stale code.
#
# The fix: never call `kina load` on a tag that could already exist. Build
# and load under a fresh, single-use random tag every run — a name that has
# never existed cannot hit the stale-tag-reuse path, whether `kina load`
# lands it in `default` only (unfixed kina) or directly in `k8s.io` (a
# cargo-built kina with the 162962c fix, which also force-tags on its own).
# The bridge below then force-retags that fresh content onto the STABLE ref
# the manifests actually pull (`docker.io/<image>:latest`) via `ctr images
# tag --force`, which — unlike `ctr images import` — does support
# overwriting an existing target. The ephemeral tag is deleted afterward so
# it doesn't accumulate across runs.
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

# build-and-load builds `dockerfile` in `context`, loads the result into
# cluster `cs` under a fresh single-use tag, then force-retags it onto
# `docker.io/<image>:latest` in containerd's k8s.io namespace — the ref the
# manifests actually pull and kubelet's CRI reads from. See the module
# docstring for why the fresh tag (not `kina load` itself) is what defeats
# the stale-digest bug.
def build-and-load [image: string, dockerfile: string, context: string] {
  let uniq = (random chars -l 8)
  let local_ref = $"($image):load-($uniq)"
  let final_ref = $"docker.io/($image):latest"

  print $"== building ($image) \(tag: load-($uniq)\) =="
  ^container build --no-cache -t $local_ref -f $dockerfile $context

  print $"== loading ($local_ref) into cluster cs =="
  ^kina load $local_ref --cluster cs

  bridge-to-k8s-io $local_ref $final_ref
  ^container image delete $local_ref
}

# bridge-to-k8s-io moves the freshly-loaded `local_ref` into containerd's
# `k8s.io` namespace (where kubelet/CRI reads from) and force-retags it onto
# `final_ref`, so a rollout restart always picks up this run's digest
# regardless of what `final_ref` pointed at before. `local_ref` is a
# single-use tag (see build-and-load), so wherever `kina load` actually put
# it — `default` (unfixed kina) or already in `k8s.io` (fixed kina) — is
# guaranteed to hold THIS run's content, never a stale one.
def bridge-to-k8s-io [local_ref: string, final_ref: string] {
  let safe = ($local_ref | str replace --all "/" "-" | str replace --all ":" "-")
  let tar = $"/tmp/($safe).tar"

  let export = (^container exec cs-control-plane ctr -n default images export $tar $local_ref | complete)
  if $export.exit_code == 0 {
    ^container exec cs-control-plane ctr -n k8s.io images import $tar
    ^container exec cs-control-plane rm -f $tar
    do -i { ^container exec cs-control-plane ctr -n default images delete $local_ref } | ignore
  }

  print $"== force-tagging ($local_ref) -> ($final_ref) in k8s.io =="
  ^container exec cs-control-plane ctr -n k8s.io images tag --force $local_ref $final_ref
  do -i { ^container exec cs-control-plane ctr -n k8s.io images delete $local_ref } | ignore
}

def load-core [] {
  build-and-load "canarysting/core" "deploy/kina/Dockerfile.core" "."
}

# Phase 4 (dashboard): frontend (dashboard/app, Next.js standalone build).
# Context is dashboard/app, not the repo root — the standalone build only
# needs its own package.json/lockfile, unlike Dockerfile.core which COPYs the
# whole repo for the go:embed bpf .o files.
def load-dashboard-web [] {
  build-and-load "canarysting/dashboard-web" "deploy/kina/Dockerfile.dashboard-web" "dashboard/app"
}

# Phase 3 (6-service mesh): tiny east-west service (deploy/m7-window/mesh).
def load-mesh [] {
  build-and-load "canarysting/mesh" "deploy/m7-window/mesh/Dockerfile" "."
}
