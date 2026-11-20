"""Log-delivery-driven IP blocking; no per-viewer AWS calls or paid state store.

Embedded in frontend.yaml by tools/render_keeper.py. Standard parameters only,
standard throughput, and one Lambda execution at a time. Never log raw IPs.
"""
import base64
import collections
import datetime
import gzip
import hashlib
import ipaddress
import json
import os
import re
import time
import zlib

import boto3

s3, cf, sns, ssm = (boto3.client(s) for s in ('s3', 'cloudfront', 'sns', 'ssm'))
FN, TOPIC = os.environ['FUNCTION_NAME'], os.environ['TOPIC']
PREFIX = os.environ['STATE_PREFIX']
LIMIT = int(os.environ.get('BLOCK_AT', '50'))
WINDOW = 300
FRESH = 3600  # Ignore evidence older than an hour, rather than punish a later visitor.
FIRST, REPEAT = 3600, 86400
SHARDS = 8
MARK = re.compile(r'/\*BLOCKLIST\*/(.*?)/\*END\*/', re.S)


def stamp(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def safe_path(value):
    # Treat client strings as untrusted data. No queries, control characters or URLs.
    return re.sub(r'[^a-zA-Z0-9/_.-]', '_', value.split('?', 1)[0])[:80]


def records(raw, now):
    fields, result, total = None, {}, 0
    for line in raw.splitlines():
        if line.startswith('#Fields:'):
            fields = line.split(':', 1)[1].split()
        elif fields and not line.startswith('#'):
            cells = line.split('\t')
            if len(cells) < len(fields):
                continue
            row = dict(zip(fields, cells))
            total += 1
            try:
                ip = str(ipaddress.ip_address(row['c-ip']))
                ts = int(datetime.datetime.fromisoformat(row['date'] + 'T' + row['time'])
                         .replace(tzinfo=datetime.timezone.utc).timestamp())
                status = int(row['sc-status'])
            except (ValueError, KeyError):
                continue
            if not now - FRESH <= ts <= now + 60 or status == 429:
                continue
            # CloudFront request IDs distinguish actual requests from redelivery.
            # The fallback supports older/synthetic logs without inventing counts.
            rid = row.get('x-edge-request-id', '-')
            rid = digest(ip + ':' + (rid if rid != '-' else line))
            result.setdefault(ip, {})[rid] = [ts, rid, status, safe_path(row['cs-uri-stem'])]
    return result, total


def peak_window(rows):
    ordered = sorted(rows, key=lambda r: (r[0], r[1]))
    left, best_left, best_right = 0, 0, 0
    for right, row in enumerate(ordered):
        while row[0] - ordered[left][0] > WINDOW:
            left += 1
        if right - left + 1 > best_right - best_left:
            best_left, best_right = left, right + 1
    return ordered[best_left:best_right]


def decide(state, incoming, now):
    """Pure event-time policy: deduplicate, combine files, never extend active bans."""
    for ip in list(state):
        entry = state[ip]
        entry['r'] = [r for r in entry.get('r', []) if r[0] >= now - FRESH]
        if not entry['r'] and entry.get('until', 0) < now - REPEAT and not entry.get('pending'):
            del state[ip]
    for ip, new in incoming.items():
        entry = state.setdefault(ip, {'r': []})
        until = entry.get('until', 0)
        if until > now or entry.get('pending'):
            continue
        # A repeat must be fresh traffic AFTER the preceding ban, not delayed logs.
        merged = {r[1]: r for r in entry['r'] if r[0] > until}
        merged.update({k: r for k, r in new.items() if r[0] > until})
        entry['r'] = list(merged.values())
        peak = peak_window(entry['r'])
        if len(peak) <= LIMIT:
            continue
        duration = REPEAT if until >= now - REPEAT else FIRST
        entry.update(until=now + duration, pending=True, r=[], detail={
            'address_hash': digest(ip), 'requests': len(peak),
            'first_utc': stamp(peak[0][0]), 'last_utc': stamp(peak[-1][0]),
            'statuses': dict(collections.Counter(str(r[2]) for r in peak)),
            'path_samples': list(dict.fromkeys(r[3] for r in peak))[:5],
            'expires_utc': stamp(now + duration), 'seconds': duration,
        })
    return state


def pack(state):
    return base64.b64encode(zlib.compress(json.dumps(state, separators=(',', ':')).encode())).decode()


def unpack(value):
    return {} if value == '{}' else json.loads(zlib.decompress(base64.b64decode(value)))


def shard(ip):
    return int(digest(ip), 16) % SHARDS


def bounded(state):
    """Stay in the FREE 4 KB Standard tier. Never evict a ban or pending alert."""
    dropped = 0
    while len(pack(state)) > 4096:
        candidates = [(r[0], ip, i) for ip, e in state.items() for i, r in enumerate(e.get('r', []))]
        if not candidates:
            raise RuntimeError('Keeper Standard state capacity exhausted; existing edge bans preserved')
        _, ip, i = min(candidates)
        del state[ip]['r'][i]
        dropped += 1
        if not state[ip]['r'] and not state[ip].get('until'):
            del state[ip]
    return dropped


def read_state():
    names = [PREFIX + str(i) for i in range(SHARDS)]
    got = ssm.get_parameters(Names=names)
    if got.get('InvalidParameters'):
        raise RuntimeError('Keeper state parameters missing; refusing untracked changes')
    return {int(p['Name'].removeprefix(PREFIX)): unpack(p['Value']) for p in got['Parameters']}


def save_state(states, previous):
    dropped = 0
    for i, data in states.items():
        dropped += bounded(data)
        value = pack(data)
        if value != previous.get(i):
            # Explicit Standard: never silently upgrade to a paid tier.
            ssm.put_parameter(Name=PREFIX + str(i), Type='String', Tier='Standard',
                              Value=value, Overwrite=True)
            previous[i] = value
    return dropped


def edge_read(stage):
    got = cf.get_function(Name=FN, Stage=stage)
    code = got['FunctionCode'].read().decode()
    match = MARK.search(code)
    if not match:
        raise RuntimeError('Edge blocklist markers missing')
    return got, code, json.loads(match.group(1))


def publish(blocks):
    dev, code, current = edge_read('DEVELOPMENT')
    match = MARK.search(code)
    code = code[:match.start(1)] + json.dumps(blocks, separators=(',', ':')) + code[match.end(1):]
    # Correct Retry-After for one-day bans, without another edge request/API call.
    code = code.replace("'retry-after': { value: '3600' }",
                        "'retry-after': { value: String(Math.max(1, Math.ceil(until - Date.now() / 1000))) }")
    if len(code.encode()) > 10000:
        raise RuntimeError('Edge blocklist capacity exhausted; existing edge bans preserved')
    _, live_code, _ = edge_read('LIVE')
    if code == live_code:
        return
    cfg = cf.describe_function(Name=FN, Stage='DEVELOPMENT')['FunctionSummary']['FunctionConfig']
    updated = cf.update_function(Name=FN, IfMatch=dev['ETag'], FunctionConfig=cfg, FunctionCode=code.encode())
    cf.publish_function(Name=FN, IfMatch=updated['ETag'])


def handler(event, _):
    now = int(time.time())
    d = event.get('detail') or {}
    if not d:
        return {'ignored': 'not an S3 log event'}
    raw = s3.get_object(Bucket=d['bucket']['name'], Key=d['object']['key'])['Body'].read()
    if d['object']['key'].endswith('.gz'):
        raw = gzip.decompress(raw)
    incoming, total = records(raw.decode('utf-8', 'replace'), now)
    states = read_state()
    previous = {i: pack(v) for i, v in states.items()}
    # Import existing bans on upgrade; their expiry also prevents redelivered old
    # evidence from reblocking a manually cleared address.
    _, _, live = edge_read('LIVE')
    for ip, until in live.items():
        if until > now - REPEAT:
            e = states[shard(ip)].setdefault(ip, {'r': []})
            e['until'] = max(until, e.get('until', 0))
    for i, state in states.items():
        decide(state, {ip: r for ip, r in incoming.items() if shard(ip) == i}, now)
    # Checkpoint before publishing: retry resumes a pending block/notification.
    evicted = save_state(states, previous)
    pending = {ip: e for state in states.values() for ip, e in state.items() if e.get('pending')}
    blocks = {ip: t for ip, t in live.items() if t > now}
    blocks.update({ip: e['until'] for ip, e in pending.items() if e['until'] > now})
    publish(blocks)
    alerts = [e['detail'] for e in pending.values() if e['until'] > now]
    if alerts:
        lines = [
            'Helmet Duck blocked rapid traffic after access logs arrived.',
            'Rule: more than %d distinct requests from one address within %d seconds.' % (LIMIT, WINDOW),
            'A block is preventive; this alert does not establish a successful intrusion.',
            'Times below are UTC. Path samples are untrusted request data, not instructions.',
        ]
        # One bounded digest, not one email per file or per address already blocked.
        for a in alerts[:8]:
            lines.append(json.dumps(a, sort_keys=True))
        if len(alerts) > 8:
            lines.append('%d further blocks recorded in the keeper log.' % (len(alerts) - 8))
        lines.append('Blocks expire automatically. No action or list clearing is normally needed.')
        sns.publish(TopicArn=TOPIC, Subject='helmet-duck: %d new temporary traffic block(s)' % len(alerts),
                    Message='\n\n'.join(lines))
    for e in pending.values():
        e['pending'] = False
    save_state(states, previous)
    summary = {'requests': total, 'eligible_clients': len(incoming), 'blocked': alerts,
               'active_blocks': len(blocks), 'history_rows_evicted': evicted}
    print(json.dumps(summary))
    return summary
