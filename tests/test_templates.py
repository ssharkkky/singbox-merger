import json
import unittest
from pathlib import Path

import main


class TemplateTests(unittest.TestCase):
    def test_both_udp_modes_are_listed(self):
        templates = {item["name"]: item for item in main.list_templates()}

        self.assertIn("dualstack", templates)
        self.assertIn("tcp-only", templates)
        self.assertIn("UDP 启用", templates["dualstack"]["description"])
        self.assertIn("UDP 禁用", templates["tcp-only"]["description"])

    def test_udp_mode_only_changes_udp_route(self):
        enabled = main.load_template("dualstack")
        disabled = main.load_template("tcp-only")

        def udp_rules(config):
            return [rule for rule in config["route"]["rules"]
                    if rule.get("network") == "udp"]

        self.assertEqual(
            [{"network": "udp", "action": "reject"}],
            udp_rules(disabled),
        )
        self.assertEqual(
            [{
                "network": "udp",
                "outbound": "🚀 节点选择",
                "action": "route",
            }],
            udp_rules(enabled),
        )

    def test_dualstack_direct_routes_native_udp_client(self):
        enabled = main.load_template("dualstack")
        disabled = main.load_template("tcp-only")

        self.assertEqual(
            {
                "user": ["nativeudp"],
                "outbound": "DIRECT",
                "action": "route",
            },
            enabled["route"]["rules"][1],
        )
        self.assertEqual(
            enabled["route"]["rules"][1],
            disabled["route"]["rules"][1],
        )

    def test_templates_are_valid_json(self):
        for path in Path(main.TEMPLATES_DIR).glob("*.json"):
            with self.subTest(path=path.name):
                json.loads(path.read_text())


if __name__ == "__main__":
    unittest.main()
