import tempfile
import unittest
from xmproxy.cli import command


class CliTest(unittest.TestCase):
    def test_upstream_record_and_intercept(self):
        with tempfile.TemporaryDirectory() as directory:
            cmd = command(["--data-dir", directory, "--upstream", "http://localhost:9090",
                           "--record", "flows.mitm", "--intercept", "~u example.com"])
        self.assertIn("upstream:http://localhost:9090", cmd)
        self.assertIn("flows.mitm", cmd)
        self.assertIn("~u example.com", cmd)
        self.assertEqual(cmd[cmd.index("--web-host") + 1], "127.0.0.1")

    def test_reject_credentials_and_invalid_ports(self):
        for args in (["--upstream", "http://user:pass@localhost:9090"], ["--port", "0"],
                     ["--port", "8081"], ["--upstream", "socks5://localhost:9090"]):
            with self.assertRaises(SystemExit):
                command(args)

    def test_upstream_only(self):
        with tempfile.TemporaryDirectory() as directory:
            cmd = command(["--data-dir", directory, "--upstream-only", "--upstream", "http://localhost:9090"])
        self.assertEqual(cmd[0], "mitmweb")
        self.assertNotIn("--ignore-hosts", cmd)
        self.assertIn("--web-port", cmd)
        for args in (["--upstream-only"],):
            with self.assertRaises(SystemExit):
                command(args)
