"""Micro DFIR's own DNS forwarder + query logger -- a from-scratch replacement for the
old dnsmasq-based opt-in DNS query logging tap, built after evaluating (and deciding
against) integrating a separate third-party DNS server (Technitium): running our own
small forwarder in this same Python codebase means no external service, no second
application's API to guess at, and no separate port/interface story to reason about.

Same safety philosophy as the dnsmasq tap it replaces: purely opt-in (never binds unless
explicitly enabled+configured), never binds 0.0.0.0 (only answers devices an admin has
deliberately pointed at this appliance's own configured IP), and forwards to real
upstream resolvers rather than attempting full recursive resolution itself -- this is a
logging proxy, not an authoritative or caching nameserver.

Standalone process (own systemd unit, config/microsoc-dns.service), matching
ueba_engine.py/coverage_snapshot.py's own "small dedicated script, not folded into the
Flask app" convention -- app.py can't bind privileged port 53 itself without complicating
the gunicorn worker model, and a crash in a hand-written DNS parser has no business being
able to take down the web UI.

Config lives in the shared `settings` table (dns_server_enabled/_bind_ip/_port/
_forwarders), polled every CONFIG_POLL_INTERVAL seconds so a change made in Settings
takes effect without needing a service restart. Every query is logged into live_logs
as app='dns_server' via a batched background flush (never a per-query synchronous
write -- this app's own established convention, see sigma_engine.py/ueba_engine.py's own
batching discipline) with the client's real source_ip and the queried domain
(query_name) -- host/username attribution is deliberately NOT attempted here (DNS itself
carries no such identity), see app.py's _resolve_dns_client_context for the best-effort,
clearly-labeled correlation done at read/display time instead.
"""
import os
import json
import socket
import sqlite3
import threading
import queue
import time
import datetime
from dnslib import DNSRecord, QTYPE, RCODE

DB_PATH = "/opt/micro-dfir/siem.db"
CONFIG_POLL_INTERVAL = 10
FLUSH_INTERVAL = 2
FLUSH_BATCH_MAX = 1000
UPSTREAM_TIMEOUT = 3
DEFAULT_FORWARDERS = ['1.1.1.1', '1.0.0.1']

_write_queue = queue.Queue()
_current_config = {'enabled': False, 'bind_ip': '', 'port': 53, 'forwarders': DEFAULT_FORWARDERS}


def _get_config_from_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT key, value FROM settings WHERE key IN "
            "('dns_server_enabled','dns_server_bind_ip','dns_server_port','dns_server_forwarders')"
        ).fetchall()
    finally:
        conn.close()
    cfg = {r['key']: r['value'] for r in rows}
    forwarders = [f.strip() for f in (cfg.get('dns_server_forwarders') or '').split(',') if f.strip()]
    try:
        port = int(cfg.get('dns_server_port') or 53)
    except (TypeError, ValueError):
        port = 53
    return {
        'enabled': cfg.get('dns_server_enabled') == '1',
        'bind_ip': (cfg.get('dns_server_bind_ip') or '').strip(),
        'port': port,
        'forwarders': forwarders or DEFAULT_FORWARDERS,
    }


def _set_status(status_dict):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    try:
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('dns_server_status', ?)",
                     (json.dumps(status_dict),))
        conn.commit()
    finally:
        conn.close()


def _forward_query(data, forwarders):
    """Forwards the raw client query bytes verbatim (same transaction ID, same question)
    to each configured upstream in order, returning the first real response. A fresh
    ephemeral socket per attempt means the OS itself guarantees this socket only ever
    receives the reply to the query it just sent -- no transaction-ID bookkeeping needed
    even under heavy concurrent load from multiple clients reusing the same 16-bit ID."""
    for upstream in forwarders:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(UPSTREAM_TIMEOUT)
            sock.sendto(data, (upstream, 53))
            resp, _ = sock.recvfrom(4096)
            return resp
        except OSError:
            continue
        finally:
            sock.close()
    return None


def _handle_query(data, client_ip, cfg):
    try:
        req = DNSRecord.parse(data)
        qname = str(req.q.qname).rstrip('.')
        qtype = QTYPE.get(req.q.qtype, str(req.q.qtype))
    except Exception:
        return None  # malformed packet -- dropped silently, same as a real resolver refusing garbage

    resp_data = _forward_query(data, cfg['forwarders'])
    rcode = 'TIMEOUT'
    if resp_data:
        try:
            rcode = RCODE.get(DNSRecord.parse(resp_data).header.rcode, 'UNKNOWN')
        except Exception:
            rcode = 'PARSE_ERROR'

    now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    _write_queue.put({
        'timestamp': now_str, 'app': 'dns_server', 'source_ip': client_ip,
        'query_name': qname, 'event_id': qtype,
        'message': f"DNS query from {client_ip}: {qname} ({qtype}) rcode={rcode}",
    })
    return resp_data


def _flush_loop():
    while True:
        time.sleep(FLUSH_INTERVAL)
        batch = []
        try:
            while len(batch) < FLUSH_BATCH_MAX:
                batch.append(_write_queue.get_nowait())
        except queue.Empty:
            pass
        if not batch:
            continue
        conn = sqlite3.connect(DB_PATH, timeout=30)
        try:
            conn.executemany(
                "INSERT INTO live_logs (timestamp, app, source_ip, query_name, event_id, message) "
                "VALUES (:timestamp, :app, :source_ip, :query_name, :event_id, :message)",
                batch
            )
            conn.commit()
        except Exception as e:
            print(f"[-] DNS server: failed to flush {len(batch)} log row(s): {e}", flush=True)
        finally:
            conn.close()


def _udp_worker(sock):
    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except OSError:
            return  # socket closed -- config changed underneath us, worker exits cleanly
        threading.Thread(target=_udp_handle_one, args=(sock, data, addr), daemon=True).start()


def _udp_handle_one(sock, data, addr):
    resp = _handle_query(data, addr[0], _current_config)
    if resp:
        try:
            sock.sendto(resp, addr)
        except OSError:
            pass


def _tcp_worker(sock):
    while True:
        try:
            conn, addr = sock.accept()
        except OSError:
            return
        threading.Thread(target=_tcp_handle_one, args=(conn, addr), daemon=True).start()


def _tcp_handle_one(conn, addr):
    # DNS-over-TCP framing: a 2-byte big-endian length prefix, then exactly that many
    # bytes of message -- needed for any response too large for a single UDP datagram
    # (EDNS0 mostly avoids this for ordinary lookups, but a client that gets a
    # UDP-truncated response is required by the DNS spec to retry over TCP).
    try:
        conn.settimeout(5)
        length_bytes = conn.recv(2)
        if len(length_bytes) < 2:
            return
        length = int.from_bytes(length_bytes, 'big')
        data = b''
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        if len(data) != length:
            return
        resp = _handle_query(data, addr[0], _current_config)
        if resp:
            conn.sendall(len(resp).to_bytes(2, 'big') + resp)
    except OSError:
        pass
    finally:
        conn.close()


def _bind_and_serve(bind_ip, port):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((bind_ip, port))
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind((bind_ip, port))
    tcp_sock.listen(20)
    threading.Thread(target=_udp_worker, args=(udp_sock,), daemon=True).start()
    threading.Thread(target=_tcp_worker, args=(tcp_sock,), daemon=True).start()
    return udp_sock, tcp_sock


def main():
    global _current_config
    threading.Thread(target=_flush_loop, daemon=True).start()
    current_sockets = (None, None)
    current_key = None
    while True:
        try:
            cfg = _get_config_from_db()
        except Exception as e:
            print(f"[-] DNS server: failed to read config: {e}", flush=True)
            time.sleep(CONFIG_POLL_INTERVAL)
            continue
        _current_config = cfg
        desired_key = (cfg['bind_ip'], cfg['port']) if cfg['enabled'] and cfg['bind_ip'] else None
        if desired_key != current_key:
            # Enabled/disabled or the bind target itself changed -- tear down and rebind
            # rather than trying to mutate live sockets. Cheap and simple; config changes
            # are rare admin actions, not a hot path.
            for s in current_sockets:
                if s:
                    try:
                        s.close()
                    except OSError:
                        pass
            current_sockets = (None, None)
            current_key = desired_key
            if desired_key:
                try:
                    current_sockets = _bind_and_serve(cfg['bind_ip'], cfg['port'])
                    _set_status({
                        'running': True, 'bind_ip': cfg['bind_ip'], 'port': cfg['port'],
                        'forwarders': cfg['forwarders'], 'error': None,
                        'started_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    })
                    print(f"[+] DNS server listening on {cfg['bind_ip']}:{cfg['port']} (UDP+TCP)", flush=True)
                except OSError as e:
                    current_key = None  # not bound -- retry on the next poll cycle
                    _set_status({
                        'running': False, 'bind_ip': cfg['bind_ip'], 'port': cfg['port'],
                        'error': str(e), 'checked_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    })
                    print(f"[-] DNS server failed to bind {cfg['bind_ip']}:{cfg['port']}: {e}", flush=True)
            else:
                _set_status({
                    'running': False, 'bind_ip': cfg['bind_ip'], 'port': cfg['port'], 'error': None,
                    'checked_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                })
        time.sleep(CONFIG_POLL_INTERVAL)


if __name__ == '__main__':
    main()
