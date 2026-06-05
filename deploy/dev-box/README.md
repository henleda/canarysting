# deploy/dev-box — the AWS Linux dev box (ROADMAP M0)

Terraform for the single EC2 box where the kernel/proxy work runs: eBPF
(CO-RE) loader + `enforce.bpf.c`, the socket-cookie identity join, the Envoy
adapter, and later the persistent staged environment (M7). macOS/arm64 can't run
these; this box can. See `docs/ROADMAP.md` §2 and M0.

## What it provisions

- **Instance:** `m7g.large` (Graviton arm64, 2 vCPU / 8 GiB), Ubuntu 24.04 LTS
  (Noble, kernel 6.8 with BTF), 40 GiB encrypted gp3 root, IMDSv2-only.
- **Network:** default VPC public subnet; a dedicated security group allowing
  **SSH from your operator IP only**, all egress.
- **Toolchain (cloud-init):** Go (pinned), clang/llvm, libbpf/libelf, bpftool,
  build-essential, Docker. Writes `/var/log/canarysting-provision.done` when done.

## Use

```sh
cd deploy/dev-box
# tfvars already holds your IP + key path; refresh the IP if your network changed:
#   curl -s https://checkip.amazonaws.com   then edit allowed_ssh_cidr
terraform init
terraform plan
terraform apply

# once apply prints outputs, wait ~2-4 min for cloud-init, then:
terraform output -raw provision_check | sh   # prints the install summary
eval "$(terraform output -raw ssh)"          # log in
```

Auth: the AWS CLI must be configured (IAM user `canarysting-dev`). The SSH key
is `~/.ssh/canarysting-dev` (generated locally; the private key never enters
Terraform state — only the public key is uploaded).

## Teardown

```sh
terraform destroy
```

Note: this box becomes the **M7 persistent environment** host, so once that
learning window starts it must stay up — don't `destroy` it casually after M7
begins. State (`terraform.tfstate`) and `terraform.tfvars` are gitignored; the
`.tf` files and `.terraform.lock.hcl` are committed.
