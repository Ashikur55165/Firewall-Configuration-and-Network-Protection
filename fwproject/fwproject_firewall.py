#!/usr/bin/env python3
"""Root-owned nftables controller for the Firewall Protection Project."""
from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

DB_PATH = Path('/opt/fwproject/instance/firewall.db')
CONFIG_PATH = Path('/etc/fwproject/config.json')
TABLE_FAMILY = 'inet'
TABLE_NAME = 'fwproject'


def run(command: list[str], *, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def load_config() -> dict:
    with CONFIG_PATH.open('r', encoding='utf-8') as handle:
        config = json.load(handle)
    network = ipaddress.ip_network(config['admin_cidr'], strict=False)
    dashboard_port = int(config.get('dashboard_port', 5000))
    ssh_port = int(config.get('ssh_port', 22))
    for value in (dashboard_port, ssh_port):
        if not 1 <= value <= 65535:
            raise ValueError('Invalid management port in /etc/fwproject/config.json')
    return {
        'admin_cidr': str(network),
        'dashboard_port': dashboard_port,
        'ssh_port': ssh_port,
    }


def load_rules() -> list[dict]:
    if not DB_PATH.exists():
        return []
    connection = sqlite3.connect(f'file:{DB_PATH}?mode=ro', uri=True)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            'SELECT id, name, action, source, protocol, port FROM rules '
            'WHERE enabled = 1 ORDER BY id ASC'
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            validate_rule(item)
            result.append(item)
        return result
    finally:
        connection.close()


def validate_rule(rule: dict) -> None:
    name = str(rule.get('name', ''))
    if not name or len(name) > 60 or any(ord(c) < 32 for c in name):
        raise ValueError(f"Invalid rule name in database (rule {rule.get('id')})")
    if rule.get('action') not in ('allow', 'block'):
        raise ValueError(f"Invalid action in rule {rule.get('id')}")
    if rule.get('protocol') not in ('tcp', 'udp', 'icmp', 'any'):
        raise ValueError(f"Invalid protocol in rule {rule.get('id')}")
    source = rule.get('source') or ''
    if source:
        ipaddress.ip_network(source, strict=False)
    port = rule.get('port')
    if port is not None:
        if rule['protocol'] not in ('tcp', 'udp'):
            raise ValueError('Ports can only be used with TCP or UDP')
        port = int(port)
        if not 1 <= port <= 65535:
            raise ValueError('Invalid port')


def source_expression(source: str, family: int | None = None) -> str:
    if not source:
        return ''
    network = ipaddress.ip_network(source, strict=False)
    if family is not None and network.version != family:
        return ''
    return f'{"ip" if network.version == 4 else "ip6"} saddr {network}'


def compile_rule(rule: dict) -> list[str]:
    """Return one or more safe nft rule lines from a validated DB record."""
    validate_rule(rule)
    source = rule.get('source') or ''
    protocol = rule['protocol']
    port = rule.get('port')
    verdict = 'accept' if rule['action'] == 'allow' else 'drop'
    base = source_expression(source)

    if protocol == 'icmp':
        families = [4, 6] if not source else [ipaddress.ip_network(source, strict=False).version]
        lines = []
        for family in families:
            source_part = source_expression(source, family)
            proto = 'icmp' if family == 4 else 'ipv6-icmp'
            parts = [part for part in (source_part, f'meta l4proto {proto}') if part]
            lines.append(' '.join(parts + ['counter', verdict]))
        return lines

    parts = [base] if base else []
    if protocol == 'tcp':
        parts.append('tcp' + (f' dport {int(port)}' if port is not None else ''))
    elif protocol == 'udp':
        parts.append('udp' + (f' dport {int(port)}' if port is not None else ''))
    elif protocol == 'any':
        if not source:
            raise ValueError('An "any protocol" rule must specify a source IP/CIDR')
    return [' '.join(parts + ['counter', verdict])]


def build_ruleset(config: dict, rules: list[dict], table_exists: bool) -> str:
    lines: list[str] = []
    if table_exists:
        lines.append(f'delete table {TABLE_FAMILY} {TABLE_NAME}')
    lines += [
        f'table {TABLE_FAMILY} {TABLE_NAME} {{',
        '  chain input {',
        '    type filter hook input priority -10; policy drop;',
        '    iifname "lo" counter accept',
        '    ct state invalid counter drop',
    ]

    # Keep the management path from the configured administrator subnet available.
    admin = ipaddress.ip_network(config['admin_cidr'], strict=False)
    family_keyword = 'ip' if admin.version == 4 else 'ip6'
    lines.append(
        f'    {family_keyword} saddr {admin} tcp dport {{ '
        f'{config["ssh_port"]}, {config["dashboard_port"]} }} counter accept'
    )

    # Explicit blocks precede established/related and user allow rules.
    for rule in rules:
        if rule['action'] == 'block':
            lines.extend('    ' + line for line in compile_rule(rule))

    lines += [
        '    ct state established,related counter accept',
        '    udp sport 67 udp dport 68 counter accept',
        '    meta l4proto icmp limit rate 10/second burst 20 packets counter accept',
        '    meta l4proto ipv6-icmp limit rate 10/second burst 20 packets counter accept',
        '    tcp flags syn limit rate over 25/second burst 50 packets counter log prefix "FWPROJECT_SYN_LIMIT: " drop',
    ]

    for rule in rules:
        if rule['action'] == 'allow':
            lines.extend('    ' + line for line in compile_rule(rule))

    lines += [
        '    limit rate 5/second burst 10 packets log prefix "FWPROJECT_DROP: "',
        '    counter drop',
        '  }',
        '}',
        '',
    ]
    return '\n'.join(lines)


def apply_firewall() -> dict:
    config = load_config()
    rules = load_rules()
    exists = subprocess.run(
        ['nft', 'list', 'table', TABLE_FAMILY, TABLE_NAME],
        text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0
    ruleset = build_ruleset(config, rules, exists)
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile('w', encoding='utf-8', delete=False) as handle:
            handle.write(ruleset)
            temp_name = handle.name
        # Syntax-check before applying. This avoids replacing the active table
        # with an invalid ruleset.
        run(['nft', '-c', '-f', temp_name])
        run(['nft', '-f', temp_name])
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)
    return {'ok': True, 'message': 'Firewall rules applied successfully.', 'enabled_rules': len(rules)}


def status() -> dict:
    result = subprocess.run(
        ['nft', '-nn', 'list', 'table', TABLE_FAMILY, TABLE_NAME],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        return {'active': False, 'ruleset': '', 'message': 'Firewall table is not currently loaded.'}
    return {'active': True, 'ruleset': result.stdout, 'message': 'Firewall table is loaded.'}


def stop() -> dict:
    result = subprocess.run(
        ['nft', 'delete', 'table', TABLE_FAMILY, TABLE_NAME],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode != 0 and 'No such file' not in (result.stderr or ''):
        raise RuntimeError(result.stderr.strip() or 'Could not remove firewall table')
    return {'ok': True, 'message': 'Project firewall table removed.'}


def main() -> int:
    if os.geteuid() != 0:
        print(json.dumps({'ok': False, 'error': 'This controller must be run through sudo.'}))
        return 1
    if len(sys.argv) != 2 or sys.argv[1] not in ('apply', 'status', 'stop'):
        print('Usage: fwproject-firewall {apply|status|stop}', file=sys.stderr)
        return 2
    try:
        result = {'apply': apply_firewall, 'status': status, 'stop': stop}[sys.argv[1]]()
        print(json.dumps(result))
        return 0
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
