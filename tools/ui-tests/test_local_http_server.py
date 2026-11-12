# SPDX-License-Identifier: GPL-3.0-or-later
import json
import sys
import threading
import unittest
from functools import partial
from http.client import HTTPConnection
from http.server import SimpleHTTPRequestHandler
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import mock_api
from local_http_server import LocalHTTPServer


class LocalServerTest(unittest.TestCase):
    def test_mock_health_works_without_reverse_dns(self) -> None:
        with (
            patch("socket.getfqdn", side_effect=AssertionError("reverse DNS must not be needed")),
            mock_api.Server(("127.0.0.1", 0), mock_api.Mock(), Path("web"), False) as server,
        ):
            self.assertEqual(server.server_name, "127.0.0.1")
            self.assertEqual(server.server_port, server.server_address[1])
            worker = threading.Thread(target=server.handle_request, daemon=True)
            server.timeout = 2
            worker.start()
            connection = HTTPConnection(*server.server_address, timeout=2)
            try:
                connection.request("GET", "/__mock/health")
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(json.loads(response.read()), {"ok": True})
            finally:
                connection.close()
                worker.join(timeout=3)
            self.assertFalse(worker.is_alive())

    def test_static_files_are_served_without_reverse_dns(self) -> None:
        with TemporaryDirectory() as directory:
            Path(directory, "index.html").write_text("<h1>Installer fixture</h1>")
            handler = partial(SimpleHTTPRequestHandler, directory=directory)
            with (
                patch("socket.getfqdn", side_effect=AssertionError("reverse DNS must not be needed")),
                LocalHTTPServer(("127.0.0.1", 0), handler) as server,
            ):
                server.timeout = 2
                worker = threading.Thread(target=server.handle_request, daemon=True)
                worker.start()
                connection = HTTPConnection(*server.server_address, timeout=2)
                try:
                    connection.request("GET", "/")
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.read(), b"<h1>Installer fixture</h1>")
                finally:
                    connection.close()
                    worker.join(timeout=3)
                self.assertFalse(worker.is_alive())

    def test_occupied_port_fails_without_switching_ports(self) -> None:
        with (
            LocalHTTPServer(("127.0.0.1", 0), SimpleHTTPRequestHandler) as server,
            self.assertRaises(OSError),
        ):
            LocalHTTPServer(server.server_address, SimpleHTTPRequestHandler)


if __name__ == "__main__":
    unittest.main()
