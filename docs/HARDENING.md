# T-Pot Sensor Hardening — Network Exposure Lockdown

How to lock T-Pot 24.04.1 management ports to admin-only access without
breaking the actual honeypot surface.  This complements (not replaces) the
"persona" customization in [HIVE_PERSONAS.md](HIVE_PERSONAS.md) — the
hardening here applies universally regardless of persona.

Status: **battle-tested** on Ubuntu 24.04 + T-Pot 24.04.1.  The four
T-Pot-specific gotchas in §2 took multiple iterations to find; documented
here so the next sensor build skips that pain.

---

## 1. What needs locking down

T-Pot exposes ~60 TCP ports by default on Ubuntu (it disables `ufw` and
ships no replacement).  Two categories:

**Honeypot / persona ports** — **MUST stay open** to the internet:
`22, 23, 25, 80, 443, 445, 1080, 1433, 3306, 5060, 5900, 8080, …`
and persona-specific ports (DICOM on 11112 for medical, S7Comm on 102
for ICS, etc.).  The whole point is to receive attacker traffic.

**Management ports** — **MUST be invisible** to the internet, allowed
only from admin source IPs:

| Port | Service |
|---|---|
| `64294` | logstash ingest |
| `64295` | host OpenSSH (sensor admin) |
| `64296` | spiderfoot |
| `64297` | Kibana (via nginx) |
| `64298` | Elasticsearch |
| `64299` | tanner_api |
| `64303` | T-Pot reverse-proxy nginx |
| `64305` | logstash HTTP input |

Leaving these wide-open is the single biggest "this is a honeypot" tell —
public Shodan / Censys indexes flag T-Pot deployments specifically by
finding any of `64294–64297` exposed.

---

## 2. The four T-Pot 24.04.1 gotchas

### Gotcha 1 — T-Pot adds wide-open INPUT ACCEPTs for **every** port

T-Pot's `~/tpotce/docker/tpotinit/dist/bin/rules.sh` runs on every
container startup (called from `entrypoint.sh`).  It appends INPUT-chain
ACCEPT rules for every port T-Pot listens on, including all the mgmt
ports above:

```
-A INPUT -p tcp -m tcp --dport 64294 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 64296 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 64297 -j ACCEPT
... etc for 64298, 64299, 64303, 64305
```

These exist to make the honeytrap/glutton NFQUEUE plumbing work, but
they have the side effect of accepting ALL traffic to those ports from
any source.  **Any DROP rule added later in the chain is unreachable.**

**Implication:** lockdown rules must be inserted at the **top** of INPUT
(positions 1, 2, 3, …) so they fire BEFORE T-Pot's appended rules.  Use
`iptables -I INPUT 1 ...` not `iptables -A INPUT ...`.

When inserting multiple rules at position 1, **insert in REVERSE order**
so the final stack reads correctly top-down.  Pattern for 8 ports × 3
rule types (ACCEPT-admin, ACCEPT-established, DROP):

```bash
for port in "${MGMT_PORTS[@]}"; do  # DROP rules first (will be pushed down)
    iptables -I INPUT 1 -p tcp --dport "$port" -j DROP
done
for port in "${MGMT_PORTS[@]}"; do  # ESTABLISHED rules next (middle layer)
    iptables -I INPUT 1 -p tcp --dport "$port" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
done
for port in "${MGMT_PORTS[@]}"; do  # ACCEPT-admin last (top of chain)
    iptables -I INPUT 1 -s "$ADMIN/32" -p tcp --dport "$port" -j ACCEPT
done
```

Final order: 8× `ACCEPT admin` → 8× `ACCEPT established` → 8× `DROP`,
filling positions 1–24.  T-Pot's wide-open ACCEPTs end up at positions
50+ and never fire for the admin's allowed mgmt ports.

### Gotcha 2 — `--ctorigdst` beats `-d` in DOCKER-USER

T-Pot's docker-compose maps several management ports to containers
(e.g., port `64297` → Kibana nginx container).  Traffic to these ports
takes a different path than host services:

```
External → PREROUTING (DNAT) → routing decision → FORWARD → DOCKER-USER → container
```

The DNAT happens in `PREROUTING` (nat table) **before** `DOCKER-USER`
runs (filter table → FORWARD).  By the time DOCKER-USER evaluates the
packet, the destination IP has already been rewritten from the sensor's
public IP to the container's internal IP (typically `172.x.x.x`).

**`-d <SENSOR_IP>/32` therefore never matches** — the post-DNAT
destination is the container, not the sensor.  The rule is inert; the
chain falls through to RETURN; docker's own ACCEPT rules then allow the
traffic.

You can verify this is happening with packet counters:

```bash
sudo iptables -L DOCKER-USER -n -v --line-numbers
```

If every ACCEPT and DROP rule shows `0 packets, 0 bytes` but the
RETURN at the end has non-zero counters, your `-d` rules aren't matching.

**Fix:** use `--ctorigdst` instead.  Conntrack tracks the **original**
(pre-NAT) destination, so this query works regardless of DNAT:

```bash
# WRONG — never matches because docker has DNAT'd the destination
iptables -A DOCKER-USER -d "$ME/32" -m conntrack --ctorigdstport "$port" -j DROP

# RIGHT — queries pre-NAT destination via conntrack
iptables -A DOCKER-USER -m conntrack --ctorigdst "$ME" --ctorigdstport "$port" -j DROP
```

Same principle as the existing `--ctorigdstport` vs `--dport`
guidance (in [the prod IPTABLES_LOCKDOWN.md playbook][prod-doc])
— extends to the destination IP too.

[prod-doc]: https://github.com/...  (link to wherever the user keeps their prod docs)

### Gotcha 3 — INPUT-chain DROPs also match loopback packets

The DROP rules from Gotcha 1 look like this:

```
-A INPUT -p tcp --dport 64298 -j DROP
```

No `-i` qualifier, no source qualifier — they match **any** packet to
that destination port, including packets arriving on the `lo` interface
from the host itself.

**Why this matters:** when a local process (autossh tunnel, observatory
sensor-discovery probe, the host's own `curl 127.0.0.1:64298`) connects
to `127.0.0.1:64298`, the SYN packet goes **out** the `lo` interface and
re-enters **in** the `lo` interface.  The re-entry traverses INPUT.  The
DROP fires.  Locally-originated traffic to mgmt-port containers dies even
though docker-proxy is happily listening on `127.0.0.1:64298`.

You can spot this in the wild:

```bash
sudo iptables -nvL INPUT --line-numbers | head -25
# Look for non-zero pkts on the DROP rule for the mgmt port that's broken.
# Confirming counter: rule 20 here had 14692 pkts / 882 KB queued up while
# the SSH tunnel watchdog reported 244 consecutive "Connection timed out"
# trying to reach the T-Pot ES port.
```

Symptom from a node2 incident: `tpoti-platform-watchdog` on the
threat-intel server failing to write to `tpoti-platform-health-*` via the
SSH tunnel, while `curl http://127.0.0.1:64298/` **on the sensor itself**
also timed out.  That second observation is the tell — if it can't reach
its own loopback ES, the tunnel obviously can't either.

**Fix:** insert `-i lo -j ACCEPT` at INPUT position 1 BEFORE any of the
mgmt-port DROPs.  Standard Linux distro practice anyway:

```bash
# Strip prior copy (idempotent)
while iptables -C INPUT -i lo -j ACCEPT 2>/dev/null; do
    iptables -D INPUT -i lo -j ACCEPT
done

# Insert at the very top of INPUT
iptables -I INPUT 1 -i lo -j ACCEPT
```

Same for IPv6 (`ip6tables -I INPUT 1 -i lo -j ACCEPT`).  After this, a
local probe should succeed:

```bash
$ curl -sS --max-time 5 -o /dev/null -w '%{http_code} %{time_total}s\n' \
       http://127.0.0.1:64298/
200 0.001s
```

The pre-existing `-s 127.0.0.1 -j ACCEPT` rule that T-Pot inserts further
down in INPUT (typically position 25+) **does not save you** — our DROPs
sit above it after Gotcha 1's "insert at top" pattern is applied, so the
DROP fires first.

### Gotcha 4 — DOCKER-USER needs an ESTABLISHED-return RETURN rule

The Gotcha 2 fix (`--ctorigdst` for DOCKER-published ports) gets the
**forward path** right: a packet from `99.18.26.20:*` → `node2:64297` (or
any docker-NAT'd mgmt port) is correctly accepted by the per-port
admin-source ACCEPT rule.

But TCP is bidirectional.  The **return path** — the SYN-ACK from the
nginx container (`172.23.0.5:64297`) back to your client — has a
different source IP (the container's, not the admin's).  In DOCKER-USER:

| Direction | source | ctorigdst | ctorigdstport | Hits which rule? |
|---|---|---|---|---|
| Forward (SYN) | `99.18.26.20` | `76.165.200.142` | `64297` | ACCEPT ✓ |
| Return (SYN-ACK) | `172.23.0.5` (container) | `76.165.200.142` | `64297` | DROP ✗ |

Because the ADMIN-allow rules are scoped `-s 99.18.26.20`, return
packets fall past them and hit the catch-all `0.0.0.0/0` DROP scoped on
`--ctorigdst $ME --ctorigdstport $port`.

You see this as: **mgmt-port DROP rule for the affected port has
non-zero packet counts even though the ACCEPT rule above it ALSO has
non-zero counts.**

```bash
sudo iptables -nvL DOCKER-USER --line-numbers | grep 64297
# 3  78  4688  ACCEPT  ...  99.18.26.20  ctorigdst 76...  ctorigdstport 64297
# 10 84  5040  DROP    ...  0.0.0.0/0    ctorigdst 76...  ctorigdstport 64297
                                                            ^ both firing! return-direction drop
```

This bites ONLY docker-NAT'd mgmt ports (e.g., 64297 nginx-Kibana,
64296 Spiderfoot, 64294 Logstash ingest, 64303 reverse-proxy, 64305
Logstash HTTP).  Host-bound services like SSH on 64295 are unaffected
because the INPUT chain (which handles them) has the standard
`-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT` rule.  DOCKER-USER
does not, by default.

**Fix:** insert a conntrack-stateful RETURN at position 1 of DOCKER-USER:

```bash
# Strip prior copy (idempotent)
while iptables -C DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN 2>/dev/null; do
    iptables -D DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
done

# Insert at the very top of DOCKER-USER
iptables -I DOCKER-USER 1 -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
```

`RETURN` (not `ACCEPT`) is the right verdict for return packets: it
returns out of DOCKER-USER so the packet continues into DOCKER-FORWARD
→ DOCKER chain → the proper container delivery path.  ACCEPT would
short-circuit those chains and could break docker's own forwarding
sometimes.

After this, a browser to `https://node2:64297` works for the admin IP.
Verify the fix:

```bash
sudo iptables -nvL DOCKER-USER --line-numbers | head
# Rule 1 should now be:
#   1  N  bytes  RETURN  ...  ctstate RELATED,ESTABLISHED
```

The counter on rule 1 should climb as soon as you reconnect.  The DROP
rules below stop catching return traffic — their packet counters stop
incrementing in normal operation.

---

## 3. The complete lockdown script

This is the working `/usr/local/bin/tpot-port-lockdown.sh` from the
node2 build.  Idempotent (safe to re-run), survives reboots via a
systemd oneshot, covers INPUT + DOCKER-USER + IPv6:

```bash
#!/bin/bash
# T-Pot port lockdown — INPUT + DOCKER-USER (with --ctorigdst for post-DNAT)
# Gotcha 3 fix included: -i lo -j ACCEPT at top of INPUT so locally-originated
# traffic to mgmt ports (e.g. autossh tunnel → 127.0.0.1:64298) isn't dropped
# by the mgmt-port DROPs (which have no -i constraint).
set -e
ME="<SENSOR_PUBLIC_IP>"
ADMIN="<YOUR_ADMIN_IP>"
MGMT_PORTS=(64294 64295 64296 64297 64298 64299 64303 64305)
MGMT_PORTS_DOCKER=(64294 64296 64297 64298 64299 64303 64305)
# Note: 64295 is host-bound SSH (not docker), so it's only in INPUT not DOCKER-USER

# ─── INPUT chain (host-bound services) ─────────────────────────────
# Strip prior copies (idempotent)
for port in "${MGMT_PORTS[@]}"; do
    while iptables -C INPUT -s "$ADMIN/32" -p tcp --dport "$port" -j ACCEPT 2>/dev/null; do
        iptables -D INPUT -s "$ADMIN/32" -p tcp --dport "$port" -j ACCEPT
    done
    while iptables -C INPUT -p tcp --dport "$port" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; do
        iptables -D INPUT -p tcp --dport "$port" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    done
    while iptables -C INPUT -p tcp --dport "$port" -j DROP 2>/dev/null; do
        iptables -D INPUT -p tcp --dport "$port" -j DROP
    done
done
while iptables -C INPUT -i lo -j ACCEPT 2>/dev/null; do
    iptables -D INPUT -i lo -j ACCEPT
done

# Insert in REVERSE so final top-of-chain order is:
#   1     -i lo -j ACCEPT            ← Gotcha 3
#   2-9   ACCEPT admin per mgmt port
#  10-17  ACCEPT RELATED,ESTABLISHED per mgmt port
#  18-25  DROP per mgmt port
for port in "${MGMT_PORTS[@]}"; do
    iptables -I INPUT 1 -p tcp --dport "$port" -j DROP
done
for port in "${MGMT_PORTS[@]}"; do
    iptables -I INPUT 1 -p tcp --dport "$port" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
done
for port in "${MGMT_PORTS[@]}"; do
    iptables -I INPUT 1 -s "$ADMIN/32" -p tcp --dport "$port" -j ACCEPT
done
# Loopback ACCEPT goes in LAST so it ends up at position 1
iptables -I INPUT 1 -i lo -j ACCEPT

# ─── DOCKER-USER chain (docker-published containers) ─────────────────
iptables -F DOCKER-USER

# Gotcha 4: ESTABLISHED-return RETURN BEFORE the admin-source ACCEPTs.
# Container→client return packets have source=container_ip (not $ADMIN),
# so without this rule they fall past every admin-allow and get dropped
# by the catch-all DROP.  Effect: forward SYN works, return SYN-ACK dies,
# client times out.
iptables -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN

for port in "${MGMT_PORTS_DOCKER[@]}"; do
    iptables -A DOCKER-USER -s "$ADMIN/32" \
        -m conntrack --ctorigdst "$ME" --ctorigdstport "$port" -j ACCEPT
done
for port in "${MGMT_PORTS_DOCKER[@]}"; do
    iptables -A DOCKER-USER \
        -m conntrack --ctorigdst "$ME" --ctorigdstport "$port" -j DROP
done
iptables -A DOCKER-USER -j RETURN

# ─── IPv6 (drop everything on mgmt ports, but allow loopback) ─────────
while ip6tables -C INPUT -i lo -j ACCEPT 2>/dev/null; do
    ip6tables -D INPUT -i lo -j ACCEPT
done
for port in "${MGMT_PORTS[@]}"; do
    ip6tables -D INPUT -p tcp --dport "$port" -j DROP 2>/dev/null || true
    ip6tables -I INPUT 1 -p tcp --dport "$port" -j DROP
done
ip6tables -I INPUT 1 -i lo -j ACCEPT

iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

echo "tpot-port-lockdown: $ADMIN allowed; INPUT (+lo ACCEPT) + DOCKER-USER (--ctorigdst) covered"
```

---

## 4. Systemd persistence

The script needs to run **after** `docker.service` so the DOCKER-USER
chain exists.  Install as a oneshot:

```ini
# /etc/systemd/system/tpot-port-lockdown.service
[Unit]
Description=Lock T-Pot mgmt ports to admin IP only
After=docker.service netfilter-persistent.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/tpot-port-lockdown.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable tpot-port-lockdown.service
```

And install `iptables-persistent` for the rules.v4/v6 to load on boot:

```bash
sudo apt-get install -y iptables-persistent netfilter-persistent
```

Note: installing `iptables-persistent` will **remove `ufw`** — they
conflict.  That's fine; we run iptables directly.

---

## 5. Verification methodology

### From the sensor itself (sanity check)

```bash
# Top of INPUT should show: rule 1 = `-i lo ACCEPT`, then 24 mgmt rules
# (8 ports × 3 types = 24, sitting at positions 2-25)
sudo iptables -L INPUT -n --line-numbers | head -26

# DOCKER-USER should show 15 rules: 7 ACCEPT, 7 DROP, 1 RETURN
sudo iptables -L DOCKER-USER -n --line-numbers

# Compact format helps spot the precise rule syntax (catches `-m tcp` vs no `-m tcp`)
sudo iptables -S INPUT | grep -- '--dport 6429'
sudo iptables -S DOCKER-USER
```

### From a known external IP (real proof)

The internal view doesn't prove lockdown — you need a probe from an IP
**not** in your allowlist.  Three good options:

| Option | How |
|---|---|
| **Cellular hotspot** | Turn off WiFi → enable hotspot → run `nmap -Pn -p 22,64294,64295,64297 <sensor>` from the connected device |
| **Production / hive host** | If you have another server outside your admin NAT, SSH to it and `nmap` from there |
| **Online port checker** | Several services (`portchecker.co`, `yougetsignal.com`) — accept arbitrary IPs |

Pure-bash probe (no nmap dep) from any external box you can SSH to:

```bash
for p in 22 64294 64295 64297; do
    result=$(timeout 3 bash -c "</dev/tcp/<SENSOR_IP>/$p" 2>&1 && echo "OPEN" || echo "FILTERED")
    printf "%-6s %s\n" "$p" "$result"
done
```

**Expected output:**
```
22     OPEN     ← Cowrie SSH or persona's public service (intentional)
64294  FILTERED
64295  FILTERED
64297  FILTERED
```

Critical: **verify the external probe IP is actually outside your
allowlist.** Use `curl ifconfig.me` from the probe host first — if it
comes back as your admin IP, you're testing from inside the allowlist
and seeing false-positive OPEN results.

### From inside the allowed admin IP (positive control)

If you have any service that connects from your admin IP, watch its
counter increment:

```bash
# Run from admin host, then check counter on sensor
sudo iptables -L INPUT -n -v --line-numbers | grep "$ADMIN" | head
```

Non-zero `pkts` and `bytes` on the admin's ACCEPT rules = admin path
working.

---

## 6. Maintenance

### After every T-Pot upgrade

T-Pot's `rules.sh` re-runs on container startup and may add new
wide-open INPUT ACCEPTs (if new honeypot ports are added).  Re-run the
lockdown to push our rules back on top:

```bash
sudo /usr/local/bin/tpot-port-lockdown.sh
```

If the management port list changes in a future T-Pot version, update
the `MGMT_PORTS` array in the script.  Check `~/tpotce/docker/tpotinit/dist/bin/rules.sh`'s
`myHOSTPORTS` variable for the canonical list per T-Pot release.

### After every reboot

The systemd oneshot handles this automatically — `iptables-persistent`
restores the saved rules, then `tpot-port-lockdown.service` re-applies
the lockdown after docker is up (in case docker resets DOCKER-USER on
startup, which it sometimes does).

### Adding a second admin IP

If a second admin source needs access (a hive orchestrator, a CI/CD
runner, etc.), modify the script to allow multiple sources.  Pattern:

```bash
# Top of /usr/local/bin/tpot-port-lockdown.sh
ADMIN_IPS=("99.18.26.20" "76.165.200.190")

# Wherever we use $ADMIN, loop over the array:
for src in "${ADMIN_IPS[@]}"; do
    for port in "${MGMT_PORTS[@]}"; do
        iptables -I INPUT 1 -s "$src/32" -p tcp --dport "$port" -j ACCEPT
    done
    for port in "${MGMT_PORTS_DOCKER[@]}"; do
        iptables -A DOCKER-USER -s "$src/32" \
            -m conntrack --ctorigdst "$ME" --ctorigdstport "$port" -j ACCEPT
    done
done
```

---

## 7. Lockout recovery

If you remove the admin allowlist by accident (e.g., during testing or
a script bug), you'll lose SSH access on 64295.

### Your CURRENT session stays alive

The `RELATED,ESTABLISHED` rule keeps your existing TCP connection
authorized even after the allow-from-admin rule is removed.  **Don't
disconnect.**  Fix it from your live shell:

```bash
# Re-insert the admin rule for SSH at top of INPUT:
sudo iptables -I INPUT 1 -s "<YOUR_ADMIN_IP>/32" -p tcp --dport 64295 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4
```

### Recovery paths (in priority order)

1. **Cloud-provider console** — KVM/IPMI/serial access via your provider's
   web console.  Always available, always works.  Use this first.
2. **A second admin IP** — if you have `ADMIN_IPS` configured with more
   than one source and only one got nuked, log in from the other.
3. **Tailscale / WireGuard / VPN** — if you've set up an out-of-band
   admin VPN that the iptables ruleset accepts (e.g., on the
   `tailscale0` interface), the VPN path bypasses the lockdown.
4. **Console with the rescue command:**
   ```bash
   sudo iptables -I INPUT 1 -s "<YOUR_NEW_IP>/32" -p tcp --dport 64295 -j ACCEPT
   ```

### Avoid lockout entirely

- **Keep your current SSH session open** while you test changes from a
  new session.
- **Allow more than one source IP** if practical (admin laptop +
  cloud-VM bastion + cellular hotspot fallback).
- **Test against the rules BEFORE saving them** — apply, verify external
  probe, THEN run `iptables-save`.  If something breaks, a reboot or
  `iptables-restore < $BACKUP` recovers.

---

## 8. What this doc does NOT cover

- **Persona customization** — see [HIVE_PERSONAS.md](HIVE_PERSONAS.md).
  Persona work changes WHICH honeypot daemons run; this doc changes
  WHO can reach the management plane.  Apply both to every sensor.
- **Outbound egress filtering** — we leave containers unrestricted
  outbound.  A compromised honeypot could pivot to internal LAN.
  Not worth fixing for a public T-Pot deployment unless the sensor
  lives inside a corporate network.
- **Persona-port hardening** — by definition the honeypot ports
  (`22`, `80`, `443`, etc.) need to be world-open.  If you want to
  restrict the *attacker* IPs that reach a specific honeypot (e.g., only
  let Cowrie SSH receive from specific networks), use the same
  DOCKER-USER `--ctorigdst` + `--ctorigdstport` pattern with the
  appropriate port number.
- **SSH key-only auth + non-default port** for `64295` — a defense in
  depth beyond firewall lockdown.  T-Pot's SSH is already set to
  `64295` (non-default); also disable password auth in `/etc/ssh/sshd_config`
  and require keys.

---

## 9. Cross-references

- [`HIVE_PERSONAS.md`](HIVE_PERSONAS.md) — the persona customization design
  that this hardening complements
- The prod-deployment `IPTABLES_LOCKDOWN.md` (in user's
  `tsec-tpot-connectors/docs/`) — the original playbook that inspired
  this doc.  This one extends it with the two T-Pot 24.04.1 gotchas
  in §2 that the prod playbook hadn't yet captured.
