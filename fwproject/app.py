#!/usr/bin/env python3
"""Web dashboard for the Linux Firewall Configuration and Protection Project."""
from __future__ import annotations

import hmac
import json
import os
import re
import sqlite3
import subprocess
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / 'instance'
DB_PATH = INSTANCE_DIR / 'firewall.db'
HELPER = '/usr/local/sbin/fwproject-firewall'
APP_USER = os.environ.get('FWPROJECT_USER', 'admin')
APP_PASSWORD = os.environ.get('FWPROJECT_PASSWORD', '')
APP_PORT = int(os.environ.get('FWPROJECT_PORT', '5000'))

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024


def get_db() -> sqlite3.Connection:
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with get_db() as connection:
        connection.execute('''
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                action TEXT NOT NULL CHECK(action IN ('allow','block')),
                source TEXT NOT NULL DEFAULT '',
                protocol TEXT NOT NULL CHECK(protocol IN ('tcp','udp','icmp','any')),
                port INTEGER NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
        ''')
        connection.commit()


def auth_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        valid = (
            auth is not None
            and hmac.compare_digest(auth.username or '', APP_USER)
            and APP_PASSWORD
            and hmac.compare_digest(auth.password or '', APP_PASSWORD)
        )
        if not valid:
            return Response(
                'Authentication required', 401,
                {'WWW-Authenticate': 'Basic realm="Firewall Project Dashboard"'},
            )
        return function(*args, **kwargs)
    return wrapper


def run_helper(command: str) -> dict:
    result = subprocess.run(
        ['sudo', '-n', HELPER, command],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
    )
    try:
        payload = json.loads(result.stdout or '{}')
    except json.JSONDecodeError:
        payload = {'ok': False, 'error': result.stderr or result.stdout or 'Invalid helper response'}
    if result.returncode != 0:
        payload.setdefault('ok', False)
        payload.setdefault('error', result.stderr.strip() or 'Firewall helper failed')
    return payload


def validate_input(data: dict) -> dict:
    name = str(data.get('name', '')).strip()
    action = str(data.get('action', '')).strip().lower()
    source = str(data.get('source', '')).strip()
    protocol = str(data.get('protocol', '')).strip().lower()
    raw_port = data.get('port', '')

    if not name or len(name) > 60 or any(ord(c) < 32 for c in name):
        raise ValueError('Rule name must contain 1–60 normal characters.')
    if action not in ('allow', 'block'):
        raise ValueError('Action must be allow or block.')
    if protocol not in ('tcp', 'udp', 'icmp', 'any'):
        raise ValueError('Protocol must be TCP, UDP, ICMP, or any.')
    if source:
        import ipaddress
        source = str(ipaddress.ip_network(source, strict=False))
    if raw_port not in ('', None):
        if protocol not in ('tcp', 'udp'):
            raise ValueError('A port can only be specified for TCP or UDP rules.')
        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            raise ValueError('Port must be a number between 1 and 65535.')
        if not 1 <= port <= 65535:
            raise ValueError('Port must be between 1 and 65535.')
    else:
        port = None
    if protocol == 'any' and not source:
        raise ValueError('For protocol “any”, specify a source IP/CIDR to avoid a blanket rule.')
    return {'name': name, 'action': action, 'source': source,
            'protocol': protocol, 'port': port}


def rule_rows() -> list[dict]:
    with get_db() as connection:
        rows = connection.execute('SELECT * FROM rules ORDER BY id DESC').fetchall()
        return [dict(row) for row in rows]


@app.get('/')
@auth_required
def index():
    return render_template('index.html')


@app.get('/api/rules')
@auth_required
def api_rules():
    return jsonify(rule_rows())


@app.post('/api/rules')
@auth_required
def api_add_rule():
    try:
        item = validate_input(request.get_json(force=True) or {})
        with get_db() as connection:
            cursor = connection.execute(
                '''INSERT INTO rules(name, action, source, protocol, port, enabled, created_at)
                   VALUES (?, ?, ?, ?, ?, 1, ?)''',
                (item['name'], item['action'], item['source'], item['protocol'],
                 item['port'], datetime.now(timezone.utc).isoformat()),
            )
            rule_id = cursor.lastrowid
            connection.commit()
        result = run_helper('apply')
        if not result.get('ok'):
            with get_db() as connection:
                connection.execute('DELETE FROM rules WHERE id = ?', (rule_id,))
                connection.commit()
            run_helper('apply')
            return jsonify({'error': result.get('error', 'Could not apply rule')}), 400
        return jsonify({'ok': True, 'message': 'Rule saved and firewall updated.', 'rules': rule_rows()}), 201
    except Exception as exc:
        return jsonify({'error': str(exc)}), 400


@app.delete('/api/rules/<int:rule_id>')
@auth_required
def api_delete_rule(rule_id: int):
    with get_db() as connection:
        row = connection.execute('SELECT id FROM rules WHERE id = ?', (rule_id,)).fetchone()
        if not row:
            return jsonify({'error': 'Rule not found'}), 404
        connection.execute('DELETE FROM rules WHERE id = ?', (rule_id,))
        connection.commit()
    result = run_helper('apply')
    if not result.get('ok'):
        return jsonify({'error': result.get('error', 'Could not apply firewall changes')}), 500
    return jsonify({'ok': True, 'message': 'Rule deleted and firewall updated.'})


@app.post('/api/rules/<int:rule_id>/toggle')
@auth_required
def api_toggle_rule(rule_id: int):
    with get_db() as connection:
        row = connection.execute('SELECT enabled FROM rules WHERE id = ?', (rule_id,)).fetchone()
        if not row:
            return jsonify({'error': 'Rule not found'}), 404
        connection.execute('UPDATE rules SET enabled = ? WHERE id = ?', (0 if row['enabled'] else 1, rule_id))
        connection.commit()
    result = run_helper('apply')
    if not result.get('ok'):
        return jsonify({'error': result.get('error', 'Could not apply firewall changes')}), 500
    return jsonify({'ok': True, 'message': 'Rule status changed and firewall updated.'})


@app.post('/api/apply')
@auth_required
def api_apply():
    result = run_helper('apply')
    return (jsonify(result), 200 if result.get('ok') else 500)


@app.get('/api/status')
@auth_required
def api_status():
    return jsonify(run_helper('status'))


@app.get('/api/logs')
@auth_required
def api_logs():
    result = subprocess.run(
        ['journalctl', '-k', '--no-pager', '-n', '300'],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
    )
    lines = [line for line in result.stdout.splitlines()
             if 'FWPROJECT_DROP:' in line or 'FWPROJECT_SYN_LIMIT:' in line]
    return jsonify({'logs': lines[-100:], 'warning': result.stderr.strip() if result.returncode else ''})


@app.get('/api/health')
@auth_required
def api_health():
    return jsonify({'ok': True, 'service': 'fwproject-dashboard'})


if __name__ == '__main__':
    init_db()
    if '--init-db' in os.sys.argv:
        print(f'Database ready: {DB_PATH}')
    else:
        app.run(host='0.0.0.0', port=APP_PORT, debug=False)
