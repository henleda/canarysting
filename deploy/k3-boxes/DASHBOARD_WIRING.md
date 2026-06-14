# Demo Visual Wall — wiring the dashboard to the FAST demo box

The compelling attacker arc runs on the **FAST cold-start demo box** (`demo-box-setup.sh`,
M=1, `-demo-escalation` dwell band) — not on the live M7 learning server. But the
already-built Next.js dashboard (the "visual wall") lives on the **M7 server**. Rather than
install Node + `next build` on a 2 GB `t4g.small` (OOM-prone), we **repoint the server's
dashboard-backend at the demo box's tap** with a reversible systemd drop-in. The engine,
baseline, and learning window on the server are **never touched** — only the
demo-supporting `dashboard-backend` process.

## Data path

```
demo box engine  --tap :8088 (0.0.0.0)-->  server dashboard-backend (drop-in -tap-addr)
                                                  |
                                            :8089 /api/overview
                                                  |
                                      server dashboard-web (Next.js :3001)
                                                  |
                                       SSH -L 3001 tunnel --> operator laptop
```

The demo box's engine must bind its tap on `0.0.0.0:8088` (not loopback) so both the
loopback attacker **and** the cross-host dashboard-backend can read it. `demo-box-setup.sh`
sets `-dashboard-tap-addr 0.0.0.0:8088` for exactly this reason.

## One-time AWS: let the server reach the demo box tap

The demo box SG must allow the server's VPC IP in on tcp/8088. (This-window values:
demo box = scope-1 `10.20.1.120`, SG `sg-09e69855f7ab640d1`; server = `10.20.1.24`.)

```bash
aws ec2 authorize-security-group-ingress --region us-east-1 \
  --group-id sg-09e69855f7ab640d1 --protocol tcp --port 8088 \
  --cidr 10.20.1.24/32
```

## On the server: the drop-in (reversible)

```bash
sudo mkdir -p /etc/systemd/system/canarysting-dashboard-backend.service.d
sudo tee /etc/systemd/system/canarysting-dashboard-backend.service.d/demo.conf >/dev/null <<'EOF'
[Service]
ExecStart=
ExecStart=/opt/canarysting/bin/dashboard-backend -tap-addr http://10.20.1.120:8088 -listen-addr 127.0.0.1:8089 -env demo-range
EOF
sudo systemctl daemon-reload
sudo systemctl restart canarysting-dashboard-backend
```

`-env demo-range` must match the demo box engine's `-scope-boundary` so the backend
filters to the demo box's events.

## Verify

```bash
# server reaches the demo box tap
curl -fsS -o /dev/null -w '%{http_code}\n' http://10.20.1.120:8088/healthz   # 200
# backend renders the demo box arc
curl -fsS http://127.0.0.1:8089/api/overview | python3 -m json.tool | grep -E 'scope|verdict|usd'
# frontend serves + proxies
curl -fsS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3001/api/overview # 200
```

A correctly-wired wall shows `scope: demo-range`, escalation to `verdict: jail`, the
real `attacker_cost` (USD, model), kernel containment, and the poison reaction.

## View the wall (operator laptop)

```bash
ssh -i ~/.ssh/canarysting-dev -L 3001:127.0.0.1:3001 ubuntu@<server-public-ip>
# then open http://localhost:3001
```

## Revert (after the demo — do this)

```bash
sudo rm /etc/systemd/system/canarysting-dashboard-backend.service.d/demo.conf
sudo systemctl daemon-reload
sudo systemctl restart canarysting-dashboard-backend   # back to the M7 server's own scope
aws ec2 revoke-security-group-ingress --region us-east-1 \
  --group-id sg-09e69855f7ab640d1 --protocol tcp --port 8088 --cidr 10.20.1.24/32
```

The drop-in is the only server-side change; deleting it fully restores the dashboard to
the live M7 deployment. Pair this with `deploy/m7-window/set-demo-posture.sh default` and
the k3-box teardown (`terraform -chdir=deploy/k3-boxes/terraform destroy`).
