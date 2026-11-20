#!/usr/bin/env python3
"""Offline policy, retry and privacy regressions. No AWS requests, no traffic flood."""
import copy
import importlib.util
import io
import json
import os
import pathlib
import sys
import types
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parent.parent
os.environ.update(FUNCTION_NAME='test-edge', TOPIC='test-topic', STATE_PREFIX='/test/state/', BLOCK_AT='50')
sys.modules['boto3'] = types.SimpleNamespace(client=lambda _: None)
spec = importlib.util.spec_from_file_location('keeper', ROOT / 'infra/keeper.py')
k = importlib.util.module_from_spec(spec)
spec.loader.exec_module(k)
NOW = 1800000000
IP = '192.0.2.1'


def rows(n, start=NOW - 100, gap=1, prefix='r', status=200, path='/'):
    return {prefix + str(i): [start + i * gap, prefix + str(i), status, path] for i in range(n)}


def logfile(data, ip=IP):
    head = '#Fields: date time c-ip sc-status cs-uri-stem x-edge-request-id\n'
    return head + ''.join(k.stamp(r[0])[:19].replace('T', '\t') + '\t' + ip + '\t' + str(r[2]) + '\t' + r[3] + '\t' + r[1] + '\n' for r in data.values())


class StateStore:
    def __init__(self):
        self.data = {'/test/state/' + str(i): '{}' for i in range(k.SHARDS)}
    def get_parameters(self, Names):
        return {'Parameters': [{'Name': n, 'Value': self.data[n]} for n in Names], 'InvalidParameters': []}
    def put_parameter(self, **kw):
        assert kw['Tier'] == 'Standard' and len(kw['Value']) <= 4096
        self.data[kw['Name']] = kw['Value']


class Edge:
    def __init__(self):
        self.dev = "function handler(event) { var blocked = /*BLOCKLIST*/{}/*END*/; return blocked; }"
        self.live = self.dev
        self.version, self.publications, self.fail = 1, 0, False
    def get_function(self, Name, Stage):
        return {'ETag': str(self.version), 'FunctionCode': io.BytesIO((self.dev if Stage == 'DEVELOPMENT' else self.live).encode())}
    def describe_function(self, **kw):
        return {'FunctionSummary': {'FunctionConfig': {'Runtime': 'cloudfront-js-2.0'}}}
    def update_function(self, **kw):
        assert kw['IfMatch'] == str(self.version)
        self.dev = kw['FunctionCode'].decode()
        self.version += 1
        return {'ETag': str(self.version)}
    def publish_function(self, **kw):
        if self.fail:
            self.fail = False
            raise RuntimeError('temporary publication failure')
        self.live = self.dev
        self.publications += 1


class Mail:
    def __init__(self): self.messages, self.fail = [], False
    def publish(self, **kw):
        if self.fail:
            self.fail = False
            raise RuntimeError('temporary SNS failure')
        self.messages.append(kw)


class Policy(unittest.TestCase):
    def test_fifty_allowed_fifty_one_blocked(self):
        state = k.decide({}, {IP: rows(50)}, NOW)
        self.assertNotIn('until', state[IP])
        state = k.decide(state, {IP: rows(51)}, NOW)
        self.assertEqual(state[IP]['until'], NOW + 3600)
        self.assertEqual(state[IP]['detail']['requests'], 51)

    def test_cross_file_and_out_of_order(self):
        allrows = rows(51)
        a, b = dict(list(allrows.items())[:25]), dict(list(allrows.items())[25:])
        for first, second in ((a, b), (b, a)):
            state = k.decide({}, {IP: first}, NOW)
            state = k.decide(state, {IP: second}, NOW + 1)
            self.assertTrue(state[IP]['pending'])

    def test_duplicate_delivery_does_not_double_count(self):
        state = k.decide({}, {IP: rows(30)}, NOW)
        state = k.decide(state, {IP: rows(30)}, NOW + 1)
        self.assertEqual(len(state[IP]['r']), 30)
        self.assertNotIn('until', state[IP])

    def test_rolling_boundary_and_slow_browsing(self):
        state = k.decide({}, {IP: rows(51, start=NOW - 300, gap=6)}, NOW)
        self.assertIn('until', state[IP])
        state = k.decide({}, {IP: rows(51, start=NOW - 350, gap=7)}, NOW)
        self.assertNotIn('until', state[IP])
        state = k.decide({}, {IP: rows(18)}, NOW)
        self.assertNotIn('until', state[IP])  # Hourly integrity monitor is not exempt by a spoofable UA.

    def test_active_ban_not_extended(self):
        state = k.decide({}, {IP: rows(51)}, NOW)
        state[IP]['pending'] = False
        state = k.decide(state, {IP: rows(100, prefix='more')}, NOW + 50)
        self.assertEqual(state[IP]['until'], NOW + 3600)
        self.assertFalse(state[IP]['pending'])

    def test_repeat_requires_post_expiry_traffic(self):
        state = k.decide({}, {IP: rows(51)}, NOW)
        state[IP]['pending'] = False
        state = k.decide(state, {IP: rows(51)}, NOW + 3601)
        self.assertEqual(state[IP]['until'], NOW + 3600)
        state = k.decide(state, {IP: rows(51, start=NOW + 3601, prefix='repeat')}, NOW + 3700)
        self.assertEqual(state[IP]['until'], NOW + 3700 + 86400)

    def test_old_reputation_expires(self):
        state = {IP: {'until': NOW - 86401, 'r': []}}
        state = k.decide(state, {IP: rows(51)}, NOW)
        self.assertEqual(state[IP]['until'], NOW + 3600)

    def test_parser_ignores_429_stale_future_and_deduplicates(self):
        for data in (rows(100, status=429), rows(51, start=NOW - 5000), rows(51, start=NOW + 1000)):
            self.assertFalse(k.records(logfile(data), NOW)[0])
        raw = logfile(rows(20))
        parsed, total = k.records(raw + raw, NOW)
        self.assertEqual(total, 40)
        self.assertEqual(len(parsed[IP]), 20)

    def test_ipv6_and_path_sanitization(self):
        data, _ = k.records(logfile(rows(51, path='/secret?token=private'), '2001:0db8::1'), NOW)
        self.assertIn('2001:db8::1', data)
        state = k.decide({}, data, NOW)
        detail = json.dumps(state['2001:db8::1']['detail'])
        self.assertNotIn('private', detail)
        self.assertNotIn('2001:', detail)

    def test_standard_size_bounded_never_paid(self):
        state = {IP: {'r': [[NOW+i, k.digest(str(i)), 200, '/'+k.digest(str(i+2000))] for i in range(1000)]}}
        self.assertGreater(k.bounded(state), 0)
        self.assertLessEqual(len(k.pack(state)), 4096)
        self.assertEqual(k.unpack(k.pack(state)), state)


class Integration(unittest.TestCase):
    def setUp(self):
        self.edge, self.store, self.mail = Edge(), StateStore(), Mail()
        k.cf, k.ssm, k.sns = self.edge, self.store, self.mail
        self.raw = logfile(rows(51, path='/.env'))
        k.s3 = types.SimpleNamespace(get_object=lambda **kw: {'Body': io.BytesIO(self.raw.encode())})
        self.clock = patch.object(k.time, 'time', return_value=NOW)
        self.clock.start()
    def tearDown(self): self.clock.stop()
    def run_event(self):
        with patch('builtins.print'):
            return k.handler({'detail': {'bucket': {'name': 'test'}, 'object': {'key': 'cloudfront/log'}}}, None)
    def test_redelivery_only_one_email_and_no_republication(self):
        first = self.run_event()
        self.run_event()
        self.assertEqual(len(self.mail.messages), 1)
        self.assertEqual(self.edge.publications, 1)
        self.assertEqual(first['active_blocks'], 1)
        self.assertNotIn(IP, json.dumps(first))
        self.assertNotIn(IP, self.mail.messages[0]['Message'])
    def test_publication_failure_retry_finishes_block_and_alert(self):
        self.edge.fail = True
        with self.assertRaises(RuntimeError): self.run_event()
        self.run_event()
        self.assertEqual(len(self.mail.messages), 1)
        self.assertIn(IP, self.edge.live)
    def test_sns_failure_retry_resends_without_extending(self):
        self.mail.fail = True
        with self.assertRaises(RuntimeError): self.run_event()
        self.run_event()
        self.assertEqual(self.edge.publications, 1)
        self.assertEqual(len(self.mail.messages), 1)
    def test_pending_expired_block_never_reactivated(self):
        self.edge.fail = True
        with self.assertRaises(RuntimeError): self.run_event()
        with patch.object(k.time, 'time', return_value=NOW+3601): self.run_event()
        self.assertNotIn(IP, self.edge.live)
        self.assertFalse(self.mail.messages)
    def test_legacy_live_ban_preserved(self):
        self.raw = logfile(rows(18))
        code = self.edge.live.replace('/*BLOCKLIST*/{}', '/*BLOCKLIST*/'+json.dumps({'192.0.2.2': NOW+1000}))
        self.edge.live = self.edge.dev = code
        self.run_event()
        self.assertIn('192.0.2.2', self.edge.live)
        self.assertFalse(self.mail.messages)
    def test_manual_clear_does_not_reapply_acknowledged_state(self):
        self.run_event()
        self.edge.live = self.edge.dev = self.edge.live.replace(k.MARK.search(self.edge.live).group(1), '{}')
        self.run_event()
        self.assertNotIn(IP, self.edge.live)
        self.assertEqual(len(self.mail.messages), 1)
    def test_cross_file_end_to_end(self):
        self.raw = logfile(rows(25))
        self.run_event()
        self.assertFalse(self.mail.messages)
        self.raw = logfile(rows(26, start=NOW-75, prefix='second'))
        self.run_event()
        self.assertEqual(len(self.mail.messages), 1)


if __name__ == '__main__': unittest.main()
