# Phase 2 — AI honeypots (Beelzebub + Galah) deployment

Persona-anchored deployment of T-Pot's two AI honeypots, tuned for
maximum believability against unattended attacker traffic. Captures
sit on the ExampleCorp persona — a fictional 12-person Baton Rouge
software consultancy at `dev.examplecorp.io`.

This directory is the canonical, version-controlled copy of what's
running on the T-Pot host. If we ever re-image the sensor, the
recovery procedure is "copy these files into `~/tpotce/data/{beelzebub,galah}/`
and run the docker-compose edits in `compose/`."

## What's in here

```
beelzebub/
  ssh-22.yaml             40 hardcoded command handlers (Outlaw kill chain,
                          uname/cat /etc/passwd/etc.) + LLM fallback for
                          everything else. Anchored to "ExampleCorp dev01".
galah/
  config.yaml             Trimmed system_prompt (~1.7 KB) + TLS profile
                          mapping → /opt/galah/config/cert/. Small enough
                          to leave headroom inside Galah's hardcoded 120s
                          LLM-request ceiling.
  rules.yaml              9 static-rule routes (most-specific first):
                            /dashboard|login|signin|admin → signin form
                            /.env (+ variants)            → fake creds
                            /wp-login.php                  → WP 6.3 login
                            /.git/config                   → realistic config
                            /robots.txt                    → noisy disallow
                            /api/v[0-9]+/login etc.        → 401 JSON
                            /services                      → 4 practices
                            /team                          → 12 people
                            /                              → landing
                          Tail paths fall through to the LLM.
  templates/
    root.json             Landing page (Next.js style, hero/grid/footer)
    services.json         4 practice areas with case studies + stacks
    team.json             12 bios: 3 leadership + 6 eng + 3 design/ops
    signin.json           GET /dashboard — clean sign-in form
    signin-fail.json      Re-render with "Invalid email or password"
                          banner. NB: not currently routed because Galah's
                          static handler doesn't read r.Body — see "Cred
                          capture mechanics" below.
    env.json              Fake .env (AKIA-prefix AWS, sk-proj OpenAI,
                          ghp_ GitHub etc.). All values are RANDOM,
                          formatted-to-look-real bait — none are real
                          credentials.
    git-config.json       Fake [remote "origin"] = examplecorp/dashboard-frontend
    robots.json           Disallow /wp-admin, /api, /admin, /dashboard
    wp-login.json         Real-shape WordPress 6.3 login form HTML
    api-login.json        JSON 401 for /api/v*/login etc.
  cert/
    openssl-dev-examplecorp.cnf
                          CSR config for the self-signed cert. To
                          regenerate (when the 90-day cert expires):
                          see "Cert renewal" below.
compose/
  docker-compose.beelzebub.snippet.yml
  docker-compose.galah.snippet.yml
                          The new services + volumes to add to
                          tpotce/docker-compose.yml. Galah has FOUR
                          volume mounts: cache, cert, config.yaml,
                          rules.yaml, templates/ (mounted at
                          /opt/galah/templates, NOT /opt/galah/config/templates
                          — Galah resolves template paths relative to
                          its WORKDIR /opt/galah).
  dot-env.example         BEELZEBUB_/GALAH_ knobs to append to tpotce/.env.
                          Replace OLLAMA_HOST with your reachable Ollama
                          host:port. The model name (qwen2.5-coder:7b) must
                          match a model already loaded in your Ollama.
```

## Port layout

T-Pot's stock setup uses ports 22/80/443 for Cowrie/Snare/H0neytr4p.
We bump those to clear the way for Beelzebub + Galah:

| Honeypot     | Phase 1 port | Phase 2 port |
|--------------|--------------|--------------|
| Cowrie SSH   | 22           | 2222         |
| Cowrie Telnet| 23           | 2223         |
| Snare        | 80           | 18080        |
| H0neytr4p    | 443          | 18443        |
| **Beelzebub**| —            | **22**       |
| **Galah HTTP**| —           | **80**       |
| **Galah HTTPS**| —          | **443**      |

This is intentional: real attackers hit 22/80/443 by default. Cowrie
and Snare continue capturing the small subset of attackers that
fingerprint the port and shift, plus benign scanners that try all
ports.

## Deployment

On a fresh T-Pot (or after re-imaging):

```bash
# 1. Append the env vars
cat compose/dot-env.example >> ~/tpotce/.env
# Edit ~/tpotce/.env and replace OLLAMA_HOST with your real Ollama host

# 2. Stage configs (paths assume default TPOT_DATA_PATH=./data)
install -D -m 0644 beelzebub/ssh-22.yaml ~/tpotce/data/beelzebub/services/ssh-22.yaml
install -D -m 0644 galah/config.yaml     ~/tpotce/data/galah/config.yaml
install -D -m 0644 galah/rules.yaml      ~/tpotce/data/galah/rules.yaml
mkdir -p ~/tpotce/data/galah/templates
install -m 0644 galah/templates/*.json   ~/tpotce/data/galah/templates/

# 3. Generate the self-signed cert (90-day; see "Cert renewal" to redo)
mkdir -p ~/tpotce/data/galah/cert
openssl req -x509 -nodes -days 90 -newkey rsa:2048 \
  -keyout ~/tpotce/data/galah/cert/dev-examplecorp.key \
  -out   ~/tpotce/data/galah/cert/dev-examplecorp.crt \
  -config galah/cert/openssl-dev-examplecorp.cnf \
  -extensions req_ext
chmod 644 ~/tpotce/data/galah/cert/dev-examplecorp.{crt,key}

# 4. Merge the compose snippets into ~/tpotce/docker-compose.yml. The
#    Cowrie/Snare port shifts must also be made (see Phase 2 sed script
#    or do it by hand — the snippets here are only the NEW services).

# 5. Bring it up
cd ~/tpotce && docker compose up -d beelzebub galah
docker compose restart cowrie snare  # for the port shifts to take effect
```

## Cred capture mechanics — a quirk

Galah's **static-rule handler short-circuits without reading
`r.Body`**. The LLM handler reads the body (to feed it into the
prompt). This means:

- A static rule for `/dashboard/login` → body is **never logged**.
- Letting `/dashboard/login` fall through to the LLM → body is logged
  in `request.body` + `request.bodySha256` of `galah.json`, EVEN IF
  the LLM call later times out at the 120s ceiling.

So we deliberately DO NOT add a static rule for the auth-submit URL.
POSTs to `/dashboard/login`, `/admin/login`, `/api/v*/login` etc.
fall through to the LLM and are captured cleanly. The pretty
`signin-fail.json` template lives here as future work — it'll get
wired up if/when we add a Galah patch or sidecar that captures bodies
on the static path.

## Cert renewal

Self-signed cert expires 90 days from generation. Calendar reminder
~2026-07-26.

```bash
cd ~/tpotce/data/galah/cert
openssl req -x509 -nodes -days 90 -newkey rsa:2048 \
  -keyout dev-examplecorp.key \
  -out   dev-examplecorp.crt \
  -config /path/to/this/repo/deploy/phase2-honeypots/galah/cert/openssl-dev-examplecorp.cnf \
  -extensions req_ext
chmod 644 dev-examplecorp.{crt,key}
cd ~/tpotce && docker compose restart galah
```

## Persona inventory — what we tell attackers

| Claim                  | Where it shows up                                    |
|------------------------|------------------------------------------------------|
| ExampleCorp LLC      | TLS cert subject, footers, header brand              |
| Baton Rouge, LA        | TLS cert L=, /team page, footer                      |
| 12-person team         | Landing card, /team page heading + stat              |
| Founded 2017           | /team CEO bio, landing copy                          |
| Next.js + Node 20 + PG | X-Powered-By header, /services page                  |
| nginx 1.18.0 (Ubuntu)  | Server header (all responses)                        |
| dev/staging banner     | Landing page yellow warning                          |
| 4 service practices    | Oil & Gas, Medical Billing, Real Estate, Custom SaaS |
| Fake .env credentials  | /.env (AKIA-prefix, sk-proj, ghp_, etc.)             |
| dev01.examplecorp.io | Beelzebub SSH banner, prompt $PS1                    |
| Outlaw kill chain ready| Beelzebub hardcoded responses for the 14 commands    |
