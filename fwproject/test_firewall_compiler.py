import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name('fwproject_firewall.py')
spec = importlib.util.spec_from_file_location('fwproject_firewall', MODULE_PATH)
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)


class FirewallCompilerTests(unittest.TestCase):
    def test_tcp_allow_rule(self):
        rule = {'id': 1, 'name': 'test', 'action': 'allow', 'source': '192.168.1.50',
                'protocol': 'tcp', 'port': 8080}
        self.assertEqual(
            fw.compile_rule(rule),
            ['ip saddr 192.168.1.50/32 tcp dport 8080 counter accept'],
        )

    def test_block_rule_uses_drop(self):
        rule = {'id': 2, 'name': 'test', 'action': 'block', 'source': '192.168.1.50/32',
                'protocol': 'udp', 'port': 9999}
        self.assertIn('counter drop', fw.compile_rule(rule)[0])

    def test_icmp_compiles_for_both_families(self):
        rule = {'id': 3, 'name': 'icmp', 'action': 'allow', 'source': '',
                'protocol': 'icmp', 'port': None}
        result = fw.compile_rule(rule)
        self.assertEqual(len(result), 2)
        self.assertIn('meta l4proto icmp', result[0])
        self.assertIn('meta l4proto ipv6-icmp', result[1])

    def test_any_protocol_requires_source(self):
        rule = {'id': 4, 'name': 'wide', 'action': 'allow', 'source': '',
                'protocol': 'any', 'port': None}
        with self.assertRaises(ValueError):
            fw.compile_rule(rule)

    def test_blocks_precede_established_and_user_allows(self):
        rules = [
            {'id': 1, 'name': 'allow', 'action': 'allow', 'source': '192.168.1.50/32',
             'protocol': 'tcp', 'port': 8080},
            {'id': 2, 'name': 'block', 'action': 'block', 'source': '192.168.1.50/32',
             'protocol': 'tcp', 'port': 8080},
        ]
        text = fw.build_ruleset(
            {'admin_cidr': '192.168.1.0/24', 'dashboard_port': 5000, 'ssh_port': 22},
            rules, False,
        )
        self.assertLess(text.index('counter drop'), text.index('ct state established'))
        self.assertLess(text.index('counter drop'), text.index('counter accept', text.index('tcp flags syn')))


if __name__ == '__main__':
    unittest.main(verbosity=2)
