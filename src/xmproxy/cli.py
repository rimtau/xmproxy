"""Start the inspection UI and proxy without invoking a shell."""
import argparse
import os
from pathlib import Path
import shutil
import sys
from urllib.parse import urlsplit


def upstream_url(value):
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or not port:
        raise argparse.ArgumentTypeError("upstream must be http[s]://host:port")
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise argparse.ArgumentTypeError("use a host and port only; credentials belong in XMPROXY_UPSTREAM_AUTH")
    return value.rstrip("/")


def command(argv=None):
    parser = argparse.ArgumentParser(description="Inspect HTTP/HTTPS and WebSocket traffic in a local web UI")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--web-host", default="127.0.0.1", help="web UI bind address; use 0.0.0.0 for remote access")
    parser.add_argument("--web-port", type=int, default=8081)
    parser.add_argument("--upstream-only", action="store_true", help="require upstream routing while retaining TLS inspection and web UI")
    parser.add_argument("--upstream", type=upstream_url)
    parser.add_argument("--trusted-ca", type=Path, help="additional CA bundle for origin/upstream TLS verification")
    parser.add_argument("--data-dir", type=Path, default=Path(".xmproxy"))
    parser.add_argument("--record", type=Path, help="save complete flows for replay; may contain secrets")
    parser.add_argument("--intercept", help="mitmproxy filter expression, e.g. '~u example.com'")
    args = parser.parse_args(argv)
    if args.upstream_only and not args.upstream:
        parser.error("--upstream-only requires --upstream")
    for port in (args.port, args.web_port):
        if not 1 <= port <= 65535:
            parser.error("ports must be between 1 and 65535")
    if args.port == args.web_port:
        parser.error("proxy and web ports must differ")
    args.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    cmd = ["mitmweb", "--listen-host", args.listen_host, "--listen-port", str(args.port),
           "--web-host", args.web_host, "--web-port", str(args.web_port),
           "--no-web-open-browser", "--set", f"confdir={args.data_dir.resolve()}"]
    if args.upstream:
        cmd += ["--mode", "upstream:" + args.upstream]
        auth = os.environ.get("XMPROXY_UPSTREAM_AUTH")
        if auth:
            cmd += ["--upstream-auth", auth]
    if args.trusted_ca:
        cmd += ["--set", f"ssl_verify_upstream_trusted_ca={args.trusted_ca.resolve()}"]
    if args.record:
        cmd += ["--save-stream-file", str(args.record)]
    if args.intercept:
        cmd += ["--intercept", args.intercept]
    return cmd


def main():
    cmd = command()
    sibling = Path(sys.executable).parent / cmd[0]
    executable = str(sibling) if sibling.is_file() else shutil.which(cmd[0])
    if not executable:
        raise SystemExit("mitmproxy executable is missing; install xmproxy dependencies first")
    os.execv(executable, cmd)
