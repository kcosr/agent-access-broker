#!/usr/bin/env python3
"""Exercise launcher identity, port conflicts, and detached startup natively."""

import importlib.util
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

sys.dont_write_bytecode = True

HELPER = Path(__file__).with_name("local-broker-process.py")
spec = importlib.util.spec_from_file_location("local_broker_process", HELPER)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class LocalBrokerProcessTests(unittest.TestCase):
    def setUp(self):
        self.executable = helper.process_identity(os.getpid())[0]

    def run_helper(self, *args):
        return subprocess.run(
            [sys.executable, str(HELPER), *map(str, args)],
            capture_output=True, text=True,
        )

    def test_identity_requires_the_executable_and_exact_config_argument(self):
        config = "/tmp/aab-demo-test/config with spaces.toml"
        with subprocess.Popen([
            sys.executable, "-c", "import time; time.sleep(30)", "--config", config,
        ]) as child:
            try:
                self.assertEqual(self.run_helper("matches", child.pid, self.executable, config).returncode, 0)
                self.assertNotEqual(self.run_helper("matches", child.pid, self.executable, config + ".other").returncode, 0)
                self.assertNotEqual(self.run_helper("matches", child.pid, "/bin/sh", config).returncode, 0)
            finally:
                child.terminate()

    def test_an_unrelated_process_with_a_config_string_is_not_a_match(self):
        with subprocess.Popen([
            sys.executable, "-c", "import time; time.sleep(30)", "/tmp/broker.toml",
        ]) as child:
            try:
                self.assertNotEqual(self.run_helper("matches", child.pid, self.executable, "/tmp/broker.toml").returncode, 0)
            finally:
                child.terminate()

    def test_port_conflict(self):
        if not sys.platform.startswith("linux"):
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen()
                port = listener.getsockname()[1]
                self.assertNotEqual(self.run_helper("check-port", "127.0.0.1", port).returncode, 0)
            self.assertEqual(self.run_helper("check-port", "127.0.0.1", port).returncode, 0)
            return
        # On Linux a bound socket that is not listening holds the port, so no
        # other process can take it between the checks, yet the helper's own
        # SO_REUSEADDR bind still finds the port free.
        with socket.socket() as reserved:
            reserved.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", port))
                listener.listen()
                self.assertNotEqual(self.run_helper("check-port", "127.0.0.1", port).returncode, 0)
            self.assertEqual(self.run_helper("check-port", "127.0.0.1", port).returncode, 0)

    def test_detached_spawn_survives_launcher_and_uses_its_log(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "broker.log"
            result = self.run_helper(
                "spawn", log, "--", sys.executable, "-u", "-c",
                "import time; print('started'); time.sleep(30)",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            pid = int(result.stdout)
            try:
                self.assertEqual(helper.process_identity(pid)[0], self.executable)
                deadline = time.monotonic() + 5
                while log.read_text() != "started\n" and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertEqual(log.read_text(), "started\n")
            finally:
                os.kill(pid, signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
