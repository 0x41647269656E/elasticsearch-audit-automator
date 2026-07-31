import unittest

import main


class BuildHandlerTests(unittest.TestCase):
    def _tunnel(self) -> main.SshTunnel:
        tunnel = main.SshTunnel.__new__(main.SshTunnel)
        tunnel.remote_host = "10.0.0.5"
        tunnel.remote_port = 9200
        return tunnel

    def test_builds_a_handler_carrying_the_ssh_transport(self) -> None:
        """A class body cannot read a same-named variable from the enclosing scope."""
        handler = self._tunnel()._build_handler("TRANSPORT")

        self.assertEqual(handler.transport, "TRANSPORT")

    def test_handler_targets_the_remote_elasticsearch_endpoint(self) -> None:
        handler = self._tunnel()._build_handler("TRANSPORT")

        self.assertEqual(handler.remote_host, "10.0.0.5")
        self.assertEqual(handler.remote_port, 9200)

    def test_handler_is_a_forward_handler(self) -> None:
        handler = self._tunnel()._build_handler("TRANSPORT")

        self.assertTrue(issubclass(handler, main.ForwardHandler))

    def test_two_tunnels_do_not_share_handler_state(self) -> None:
        first = self._tunnel()
        second = main.SshTunnel.__new__(main.SshTunnel)
        second.remote_host = "10.0.0.9"
        second.remote_port = 9201

        handler_a = first._build_handler("TRANSPORT_A")
        handler_b = second._build_handler("TRANSPORT_B")

        self.assertEqual(handler_a.transport, "TRANSPORT_A")
        self.assertEqual(handler_a.remote_host, "10.0.0.5")
        self.assertEqual(handler_b.transport, "TRANSPORT_B")
        self.assertEqual(handler_b.remote_host, "10.0.0.9")


if __name__ == "__main__":
    unittest.main()
