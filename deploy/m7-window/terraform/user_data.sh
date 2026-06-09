#!/usr/bin/env bash
# Client box provisioning: install Go (to build the generator/prober) and
# configure the ENI's secondary private IPs on the OS interface on every boot, so
# the generator/prober can bind them as distinct source identities. Reboot-safe.
set -euxo pipefail

GO_VER=1.22.12
curl -fsSL "https://go.dev/dl/go${GO_VER}.linux-arm64.tar.gz" -o /tmp/go.tgz
rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz
grep -q '/usr/local/go/bin' /home/ubuntu/.profile || \
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> /home/ubuntu/.profile

# Configure every secondary private IP from IMDS onto the primary interface.
cat >/usr/local/bin/canarysting-secondary-ips.sh <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
TOKEN=$(curl -fsS -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 120")
imds() { curl -fsS -H "X-aws-ec2-metadata-token: $TOKEN" "$@"; }
MAC=$(imds http://169.254.169.254/latest/meta-data/network/interfaces/macs/ | head -1 | tr -d '/')
IPS=$(imds "http://169.254.169.254/latest/meta-data/network/interfaces/macs/$MAC/local-ipv4s")
PRIMARY=$(echo "$IPS" | head -1)
IFACE=$(ip -o route get 169.254.169.254 | awk '{print $5; exit}')
PREFIX=$(ip -o -f inet addr show "$IFACE" | awk '{print $4}' | head -1 | cut -d/ -f2)
for ip in $IPS; do
  [ "$ip" = "$PRIMARY" ] && continue
  ip addr replace "$ip/${PREFIX:-24}" dev "$IFACE"
done
EOS
chmod +x /usr/local/bin/canarysting-secondary-ips.sh

cat >/etc/systemd/system/canarysting-secondary-ips.service <<'EOS'
[Unit]
Description=Configure CanarySting secondary private IPs from IMDS
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/canarysting-secondary-ips.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOS

systemctl daemon-reload
systemctl enable --now canarysting-secondary-ips.service
touch /var/log/canarysting-provision.done
