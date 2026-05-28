#!/bin/bash
# Phase 2 soak snapshot — gather honeypot capture stats from T-Pot.
# Runs over SSH against the live T-Pot. Stays under 80 lines of output.
set -euo pipefail
SSHCMD="ssh -o StrictHostKeyChecking=no -i /opt/tpot2cti/ssh-keys/id_ed25519 -p 64295 mike@76.165.200.142"

echo "═══ $(date -u +%Y-%m-%dT%H:%M:%SZ) — Phase 2 soak snapshot ═══"
echo ""

# Beelzebub
echo "── Beelzebub (SSH honeypot) ──"
$SSHCMD '
total=$(wc -l < ~/tpotce/data/beelzebub/log/beelzebub.json)
attempts=$(grep -c "New SSH attempt" ~/tpotce/data/beelzebub/log/beelzebub.json || echo 0)
sessions=$(grep -c "New SSH Inline Session" ~/tpotce/data/beelzebub/log/beelzebub.json || echo 0)
uniq_ips=$(grep -oE "\"src_ip\":\"[0-9.]+\"" ~/tpotce/data/beelzebub/log/beelzebub.json | sort -u | wc -l)
uniq_user=$(grep -oE "\"username\":\"[^\"]*\"" ~/tpotce/data/beelzebub/log/beelzebub.json | sort -u | wc -l)
uniq_pw=$(grep -oE "\"password\":\"[^\"]*\"" ~/tpotce/data/beelzebub/log/beelzebub.json | sort -u | wc -l)
echo "  events:        $total"
echo "  auth attempts: $attempts"
echo "  cmd sessions:  $sessions"
echo "  uniq src IPs:  $uniq_ips"
echo "  uniq users:    $uniq_user"
echo "  uniq passwds:  $uniq_pw"
'

echo ""
echo "── Top 5 attacker IPs (by event count) ──"
$SSHCMD 'grep -oE "\"src_ip\":\"[0-9.]+\"" ~/tpotce/data/beelzebub/log/beelzebub.json | sort | uniq -c | sort -rn | head -5 | awk "{print \"  \" \$0}"'

echo ""
echo "── Top 5 commands attackers ran ──"
$SSHCMD 'grep "Inline Session" ~/tpotce/data/beelzebub/log/beelzebub.json | python3 -c "
import sys, json
from collections import Counter
c = Counter()
for line in sys.stdin:
    try:
        ev = json.loads(line)
        if cmd := ev.get(\"input\"):
            c[cmd] += 1
    except: pass
for cmd, n in c.most_common(5):
    print(f\"  {n:4d}  {cmd[:90]}\")
"'

echo ""
echo "── Galah (HTTP honeypot) ──"
$SSHCMD '
total=$(wc -l < ~/tpotce/data/galah/log/galah.json)
gets=$(grep -c "\"request.method\":\"GET\"" ~/tpotce/data/galah/log/galah.json || echo 0)
posts=$(grep -c "\"request.method\":\"POST\"" ~/tpotce/data/galah/log/galah.json || echo 0)
posts_w_body=$(python3 -c "
import json
n=0
for line in open(\"/home/mike/tpotce/data/galah/log/galah.json\"):
    try:
        ev = json.loads(line)
        if ev.get(\"request.body\"): n += 1
    except: pass
print(n)
")
uniq_ips=$(grep -oE "\"src_ip\":\"[0-9.]+\"" ~/tpotce/data/galah/log/galah.json | sort -u | wc -l)
echo "  events:           $total"
echo "  GETs:             $gets"
echo "  POSTs:            $posts"
echo "  POSTs with body:  $posts_w_body  ← credential-capture candidates"
echo "  uniq src IPs:     $uniq_ips"
'

echo ""
echo "── Top 5 Galah request paths ──"
$SSHCMD 'python3 -c "
import json
from collections import Counter
c = Counter()
for line in open(\"/home/mike/tpotce/data/galah/log/galah.json\"):
    try:
        ev = json.loads(line)
        c[ev.get(\"request.requestURI\", \"?\")] += 1
    except: pass
for p, n in c.most_common(5):
    print(f\"  {n:4d}  {p[:80]}\")
"'

echo ""
echo "── Captured POST bodies (cred-capture proof) ──"
$SSHCMD 'python3 /dev/stdin <<PYEOF
import json
seen=set()
for line in open("/home/mike/tpotce/data/galah/log/galah.json"):
    try:
        ev = json.loads(line)
        body = ev.get("request.body", "")
        if body and ev.get("request.method") == "POST":
            if body not in seen:
                seen.add(body)
                src = ev.get("src_ip", "?")
                uri = ev.get("request.requestURI", "?")[:30]
                print(f"  {src:16s}  {uri:30s}  {body[:120]}")
                if len(seen) >= 5: break
    except Exception: pass
PYEOF'

echo ""
echo "── Importer: last cycle stats ──"
docker exec tpot2cti-core tail -200 /var/log/tpot2cti/tpot2cti.log 2>/dev/null | grep "complete in" | tail -2 | python3 -c "
import sys, json, re
for line in sys.stdin:
    try:
        m = re.search(r'\"message\": \"([^\"]+)\"', line)
        if m:
            print(f'  {m.group(1)[:160]}')
    except: pass
"

echo ""
echo "═══ end snapshot ═══"
