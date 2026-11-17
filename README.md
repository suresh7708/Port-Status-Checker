#!/usr/bin/env python3
"""Port Status Checker

Checks whether a single TCP port on a given host is open or closed by
attempting a connection.

Usage:
    python port_status_checker.py 80
    python port_status_checker.py 22 --host example.com
    python port_status_checker.py 443 --host 192.168.1.10 --timeout 3
    python port_status_checker.py            (interactive mode)

Only check systems you own or have permission to test.
"""

import argparse
import errno
import socket
import sys

COMMON_SERVICES = {
    20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    465: "SMTPS", 587: "SMTP (submission)", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP (alternate)", 27017: "MongoDB",
}


def validate_port(value) -> int:
    """Convert input to a valid port number (1-65535) or raise ValueError."""
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"'{value}' is not a valid number.")
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    return port


def check_port(host: str, port: int, timeout: float = 2.0) -> tuple[str, str]:
    """Try to connect to host:port. Returns (status, explanation)."""
    try:
        # Resolve once so we can report DNS problems separately.
        family, socktype, proto, _, sockaddr = socket.getaddrinfo(
            host, port, type=socket.SOCK_STREAM
        )[0]
    except socket.gaierror:
        return "ERROR", f"Could not resolve host '{host}'."

    with socket.socket(family, socktype, proto) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect(sockaddr)
            return "OPEN", "A service accepted the connection."
        except socket.timeout:
            return (
                "CLOSED/FILTERED",
                "No response before the timeout. A firewall is likely dropping packets.",
            )
        except ConnectionRefusedError:
            return "CLOSED", "Connection refused. The host is reachable but nothing is listening."
        except OSError as exc:
            if exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
                return "ERROR", "Network or host unreachable."
            return "ERROR", f"Connection failed: {exc}"


def report(host: str, port: int, timeout: float) -> str:
    status, explanation = check_port(host, port, timeout)
    service = COMMON_SERVICES.get(port)
    label = f"{port} ({service})" if service else str(port)
    print(f"\nHost   : {host}")
    print(f"Port   : {label}")
    print(f"Status : {status}")
    print(f"Detail : {explanation}\n")
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description="Check whether a TCP port is open or closed.")
    parser.add_argument("port", nargs="?", help="Port number to check (1-65535)")
    parser.add_argument("--host", default="127.0.0.1", help="Host to check (default: 127.0.0.1)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Timeout in seconds (default: 2)")
    args = parser.parse_args()

    port_input = args.port
    host = args.host

    # Interactive mode when no port is given on the command line.
    if port_input is None:
        try:
            host = input("Host [127.0.0.1]: ").strip() or "127.0.0.1"
            port_input = input("Port number: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return 1

    try:
        port = validate_port(port_input)
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1

    status = report(host, port, args.timeout)
    return 0 if status == "OPEN" else 2


if __name__ == "__main__":
    sys.exit(main())
    
