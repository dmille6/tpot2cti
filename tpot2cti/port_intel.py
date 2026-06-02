"""Port / service intelligence + payload fingerprinting for catchall honeypots.

Honeytrap (and the generic fallback) log raw TCP/UDP probes with little more
than a ``dest_port`` and an occasional payload blob.  On their own those make
thin, near-useless indicators ("malicious IP, labelled tcp-catchall").  The
*pattern across a burst* — which ports an IP swept, whether they map to a known
service, what the payload looks like — is the actual intel.  This module turns
those raw signals into:

  * service names for well-known ports (``2082 → cPanel/WHM``),
  * a scan-shape classification + pivotable labels
    (``scan:vertical``, ``target:cpanel``),
  * payload fingerprints for the valuable non-empty minority
    (HTTP probes, TLS ClientHello, known scanner/botnet signatures).

It is deliberately pure (no project imports) so both the parser layer and the
STIX builder can call it without circular-import gymnastics, and so it is
trivially unit-testable.

See docs/parsers/honeytrap.md for how the Honeytrap parser/builder consume it.
"""

from __future__ import annotations

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Port → service map
# ---------------------------------------------------------------------------
# Curated, not exhaustive: the ports attackers actually sweep T-Pot for. Each
# value is ``(service_label, family_token)`` where ``family_token`` is the
# lowercase slug used to build a ``target:<family>`` label (so a cPanel sweep
# across 2082/2083/2086/2087 yields ONE ``target:cpanel`` label, not four).

PORT_SERVICES: dict[int, tuple[str, str]] = {
    21: ("FTP", "ftp"),
    22: ("SSH", "ssh"),
    23: ("Telnet", "telnet"),
    2323: ("Telnet-alt", "telnet"),
    25: ("SMTP", "smtp"),
    53: ("DNS", "dns"),
    80: ("HTTP", "http"),
    81: ("HTTP-alt", "http"),
    88: ("Kerberos", "kerberos"),
    110: ("POP3", "pop3"),
    111: ("RPCbind", "rpc"),
    135: ("MSRPC", "msrpc"),
    137: ("NetBIOS", "netbios"),
    139: ("NetBIOS-SSN", "smb"),
    143: ("IMAP", "imap"),
    161: ("SNMP", "snmp"),
    389: ("LDAP", "ldap"),
    443: ("HTTPS", "https"),
    445: ("SMB", "smb"),
    465: ("SMTPS", "smtp"),
    512: ("rexec", "r-services"),
    513: ("rlogin", "r-services"),
    514: ("rsh/syslog", "r-services"),
    587: ("SMTP-submission", "smtp"),
    623: ("IPMI", "ipmi"),
    631: ("IPP/CUPS", "ipp"),
    993: ("IMAPS", "imap"),
    995: ("POP3S", "pop3"),
    1025: ("MS-RPC-alt", "msrpc"),
    1080: ("SOCKS", "proxy"),
    1099: ("Java-RMI", "rmi"),
    1433: ("MS-SQL", "mssql"),
    1521: ("Oracle-DB", "oracle"),
    1723: ("PPTP", "vpn"),
    1883: ("MQTT", "mqtt"),
    2049: ("NFS", "nfs"),
    2082: ("cPanel", "cpanel"),
    2083: ("cPanel-SSL", "cpanel"),
    2086: ("WHM", "cpanel"),
    2087: ("WHM-SSL", "cpanel"),
    2095: ("cPanel-webmail", "cpanel"),
    2096: ("cPanel-webmail-SSL", "cpanel"),
    2222: ("SSH-alt", "ssh"),
    2375: ("Docker-API", "docker"),
    2376: ("Docker-API-TLS", "docker"),
    2379: ("etcd", "etcd"),
    3000: ("HTTP-dev/Grafana", "http"),
    3128: ("Squid-proxy", "proxy"),
    3306: ("MySQL", "mysql"),
    3389: ("RDP", "rdp"),
    3690: ("SVN", "svn"),
    4444: ("Metasploit/CobaltStrike", "c2"),
    5000: ("HTTP-UPnP/Docker-registry", "http"),
    5432: ("PostgreSQL", "postgres"),
    5555: ("ADB/Android", "adb"),
    5601: ("Kibana", "kibana"),
    5672: ("AMQP/RabbitMQ", "amqp"),
    5900: ("VNC", "vnc"),
    5901: ("VNC-1", "vnc"),
    5984: ("CouchDB", "couchdb"),
    6000: ("X11", "x11"),
    6379: ("Redis", "redis"),
    6443: ("Kubernetes-API", "kubernetes"),
    7001: ("WebLogic", "weblogic"),
    8000: ("HTTP-alt", "http"),
    8008: ("HTTP-alt", "http"),
    8009: ("AJP", "ajp"),
    8080: ("HTTP-proxy/alt", "http"),
    8081: ("HTTP-alt", "http"),
    8086: ("InfluxDB", "influxdb"),
    8088: ("HTTP-alt/Hadoop", "http"),
    8443: ("HTTPS-alt", "https"),
    8888: ("HTTP-alt", "http"),
    9000: ("HTTP-alt/SonarQube", "http"),
    9001: ("Tor/Supervisor", "http"),
    9042: ("Cassandra", "cassandra"),
    9092: ("Kafka", "kafka"),
    9200: ("Elasticsearch", "elasticsearch"),
    9300: ("Elasticsearch-transport", "elasticsearch"),
    10000: ("Webmin", "webmin"),
    11211: ("Memcached", "memcached"),
    27017: ("MongoDB", "mongodb"),
    50070: ("Hadoop-HDFS", "hadoop"),
}


def service_for_port(port: Optional[int]) -> Optional[str]:
    """Return the human service label for a port, or ``None`` if unknown."""
    if port is None:
        return None
    entry = PORT_SERVICES.get(int(port)) if _is_int(port) else None
    return entry[0] if entry else None


def family_for_port(port: Optional[int]) -> Optional[str]:
    """Return the ``target:<family>`` slug for a port, or ``None``."""
    if port is None or not _is_int(port):
        return None
    entry = PORT_SERVICES.get(int(port))
    return entry[1] if entry else None


def summarize_ports(ports, *, cap: int = 12) -> str:
    """Render a sorted, capped port list with service annotations.

    Example: ``{2082, 2086, 2087, 22}`` →
    ``"tcp/22 (SSH), tcp/2082 (cPanel), tcp/2086 (WHM), tcp/2087 (WHM-SSL)"``.
    Ports beyond ``cap`` are summarized as ``"… +N more"`` so a 5000-port
    sweep doesn't produce a multi-KB string.
    """
    clean = sorted({int(p) for p in ports if _is_int(p)})
    if not clean:
        return ""
    shown = clean[:cap]
    parts: list[str] = []
    for p in shown:
        svc = service_for_port(p)
        parts.append(f"tcp/{p} ({svc})" if svc else f"tcp/{p}")
    extra = len(clean) - len(shown)
    if extra > 0:
        parts.append(f"… +{extra} more")
    return ", ".join(parts)


def classify_scan(ports) -> tuple[list[str], str]:
    """Classify a destination-port set into (labels, human phrase).

    Labels are pivotable in OpenCTI:
      * ``scan:single`` / ``scan:multi-port`` / ``scan:vertical`` — shape,
      * ``target:<family>`` — one per distinct service family swept,
      * ``recon:broad`` — many distinct families touched (untargeted sweep).

    The phrase is a one-line English summary for the indicator description.
    """
    clean = sorted({int(p) for p in ports if _is_int(p)})
    labels: list[str] = []
    if not clean:
        return labels, "no destination port recorded"

    n = len(clean)
    if n == 1:
        labels.append("scan:single")
        shape = "single-port probe"
    elif n <= 5:
        labels.append("scan:multi-port")
        shape = f"{n}-port probe"
    else:
        labels.append("scan:vertical")
        shape = f"vertical port scan ({n} ports)"

    families = sorted({fam for p in clean if (fam := family_for_port(p))})
    for fam in families:
        labels.append(f"target:{fam}")
    if len(families) >= 4:
        labels.append("recon:broad")

    if families:
        fam_phrase = ", ".join(families)
        phrase = f"{shape} targeting {fam_phrase}"
    else:
        phrase = f"{shape} on unmapped ports"
    return labels, phrase


# ---------------------------------------------------------------------------
# Payload fingerprinting
# ---------------------------------------------------------------------------
# High-confidence signatures only.  Each match yields (label, summary). The
# label is attached to the indicator/sighting; the summary feeds the human
# description.  Order matters — first match wins.

_HTTP_METHOD_RE = re.compile(
    r"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|CONNECT|TRACE|PATCH)\s+(\S+)\s+HTTP/",
    re.IGNORECASE,
)
# Known scanner / botnet markers found in printable payloads. Conservative
# substring tests — each is distinctive enough to avoid false positives.
_PAYLOAD_SIGS: list[tuple[str, str, str]] = [
    # (needle, label, human summary)
    ("zgrab", "scanner:zgrab", "ZGrab / Censys-style internet scanner"),
    ("masscan", "scanner:masscan", "masscan probe"),
    ("nmap", "scanner:nmap", "Nmap service probe"),
    ("l9scan", "scanner:leakix", "LeakIX (l9) scanner"),
    ("netsystemsresearch", "scanner:netsystems", "NetSystems research scanner"),
    ("censys", "scanner:censys", "Censys scanner"),
    ("paloaltonetworks", "scanner:paloalto", "Palo Alto / Expanse scanner"),
    ("internet-measurement", "scanner:driftnet", "Driftnet internet-measurement"),
    ("/shell?cd+/tmp", "botnet:mirai", "Mirai-style wget/tftp dropper"),
    ("busybox", "botnet:mirai", "Mirai/Gafgyt BusyBox probe"),
    ("/bin/busybox", "botnet:mirai", "Mirai/Gafgyt BusyBox probe"),
    ("tr-064", "exploit:tr064", "TR-064 SOAP exploit (router takeover)"),
    ("soap:body", "exploit:soap", "SOAP request (CPE/router exploit)"),
    ("${jndi:", "exploit:log4shell", "Log4Shell (CVE-2021-44228) JNDI probe"),
    ("/cgi-bin/", "exploit:cgi", "CGI exploit probe"),
    ("hello", "probe:hello", "generic banner/hello probe"),
]
# Binary/leading-byte fingerprints keyed off the hex payload.
_HEX_SIGS: list[tuple[str, str, str]] = [
    ("160301", "proto:tls", "TLS 1.0+ ClientHello"),
    ("160302", "proto:tls", "TLS 1.1 ClientHello"),
    ("160303", "proto:tls", "TLS 1.2 ClientHello"),
    ("5353482d", "proto:ssh", "SSH protocol banner"),  # "SSH-"
    ("0000", "proto:smb-or-null", "null/length-prefixed probe"),
]


def fingerprint_payload(
    printable: Optional[str], hex_str: Optional[str]
) -> Optional[dict]:
    """Best-effort fingerprint of a captured probe payload.

    Returns ``None`` for empty payloads.  Otherwise a dict::

        {"label": "scanner:zgrab", "summary": "ZGrab ... scanner",
         "http": {"method": "GET", "path": "/"} | None}

    ``label`` may be ``None`` if bytes were captured but matched no signature
    (the caller still knows *something* was sent, which is itself signal).
    """
    printable = (printable or "").strip()
    hex_str = (hex_str or "").strip().lower()
    if not printable and not hex_str:
        return None

    result: dict = {"label": None, "summary": None, "http": None}

    # HTTP request line — extract method + path (the most useful probe shape).
    if printable:
        m = _HTTP_METHOD_RE.match(printable)
        if m:
            method, path = m.group(1).upper(), m.group(2)
            result["http"] = {"method": method, "path": path[:200]}
            result["label"] = "proto:http"
            result["summary"] = f"HTTP {method} {path[:120]}"
            # An HTTP probe can ALSO carry a scanner UA — let sig scan refine.

        low = printable.lower()
        for needle, label, summary in _PAYLOAD_SIGS:
            if needle in low:
                # Scanner/exploit signature is more specific than bare HTTP.
                result["label"] = label
                # Keep the HTTP request-line summary if we have it, append sig.
                if result["summary"] and label.startswith(("scanner:", "botnet:", "exploit:")):
                    result["summary"] = f"{result['summary']} — {summary}"
                else:
                    result["summary"] = summary
                break

    if result["label"] is None and hex_str:
        for prefix, label, summary in _HEX_SIGS:
            if hex_str.startswith(prefix):
                result["label"] = label
                result["summary"] = summary
                break

    if result["label"] is None and result["summary"] is None:
        nbytes = len(hex_str) // 2 if hex_str else len(printable)
        result["summary"] = f"{nbytes}B payload, no known signature"
    return result


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _is_int(v) -> bool:
    try:
        int(v)
        return True
    except (TypeError, ValueError):
        return False
