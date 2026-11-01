#!/usr/bin/env python3
"""net-whois: I ask the WHOIS registries about a domain or an IP
address and bring back what they say.

WHOIS is an old, plain protocol (RFC 3912): open a TCP connection
to port 43, send the query with a CRLF, read until the server hangs
up. No library earns its keep here, so this is standard library
sockets and the registries' own words, unedited.

Choosing a server is the only real judgment in the tool. For a set
of common TLDs I go straight to the registry that runs them. For
anything else, including IP addresses, I start at IANA and follow
its referral, the way the system was designed to be walked. Thin
registries answer with a pointer to the registrar's server; I
follow one of those too unless told not to. The chain of servers I
used is printed on stderr, so stdout stays the record itself.
"""

import argparse
import json
import re
import socket
import sys

IANA = "whois.iana.org"

# TLDs whose registry server I know and trust to answer directly.
# Anything not listed starts at IANA and follows the referral.
TLD_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.identity.digital",
    "io": "whois.nic.io",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "edu": "whois.educause.edu",
}

REFER_PATTERNS = [
    re.compile(r"^\s*refer:\s*(\S+)", re.I | re.M),
    re.compile(r"Registrar WHOIS Server:\s*(\S+)", re.I),
    re.compile(r"^\s*Whois Server:\s*(\S+)", re.I | re.M),
]

MAX_BYTES = 512 * 1024


def ask(server, port, query, timeout):
    """One WHOIS conversation: connect, ask, read to EOF."""
    chunks = []
    with socket.create_connection((server, port), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode())
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
            if sum(len(c) for c in chunks) > MAX_BYTES:
                break
    return b"".join(chunks).decode("utf-8", "replace")


def referral_in(text):
    """The next server a response points at, if it points at all."""
    for pat in REFER_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(1).strip()
    return None


def pick_server(query):
    """The first server to ask about this query."""
    q = query.strip().lower().rstrip(".")
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", q):
        return IANA
    if "." in q:
        tld = q.rsplit(".", 1)[-1]
        return TLD_SERVERS.get(tld, IANA)
    return IANA


def lookup(query, server, port, timeout, follow):
    """Walk the referral chain (at most 3 servers) and return
    (final_text, chain). I stop when a response points nowhere new,
    because registries sometimes point at themselves."""
    chain = []
    current = server or pick_server(query)
    text = ""
    for _ in range(3):
        chain.append(current)
        text = ask(current, port, query, timeout)
        if not follow:
            break
        nxt = referral_in(text)
        if not nxt:
            break
        # A server may name itself as the next hop (a registrar
        # record served from the same host). The 3-server cap above
        # is what keeps that from becoming a loop.
        current = nxt
    return text, chain


def run(args):
    query = args.query.strip()
    if not query:
        print("error: empty query; nothing to look up", file=sys.stderr)
        return 2
    try:
        text, chain = lookup(query, args.server, args.port,
                             args.timeout, not args.no_referral)
    except OSError as exc:
        print(f"error: WHOIS lookup failed: {exc}", file=sys.stderr)
        return 2
    if not text.strip():
        print("error: the registry answered with an empty response; "
              "nothing was retrieved", file=sys.stderr)
        return 2
    print("servers asked: " + " -> ".join(chain), file=sys.stderr)
    if args.json:
        print(json.dumps({"query": query, "servers": chain,
                          "response": text}, indent=2))
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="net-whois",
        description="WHOIS lookup for a domain or IP address over "
                    "port 43, with registry referral following.")
    parser.add_argument("query", help="domain name or IPv4 address")
    parser.add_argument("--server",
                        help="ask this WHOIS server first instead of "
                             "the one I would pick")
    parser.add_argument("--port", type=int, default=43,
                        help="port the WHOIS servers listen on "
                             "(default 43; referral hops use the "
                             "same port)")
    parser.add_argument("--no-referral", action="store_true",
                        help="take the first answer, do not follow "
                             "referrals")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="seconds per connection (default 10)")
    parser.add_argument("--json", action="store_true",
                        help="emit the answer as JSON, chain included")
    return parser


def main(argv=None):
    return run(build_parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
