import unittest

import main

LEAF = b"\x30\x82leaf"
INTERMEDIATE = b"\x30\x82intermediate"
ROOT = b"\x30\x82root"


class VerifiedChainSocket:
    def get_verified_chain(self):
        return [LEAF, INTERMEDIATE, ROOT]

    def get_unverified_chain(self):
        return [LEAF, INTERMEDIATE]

    def getpeercert(self, binary_form=False):
        return LEAF


class UnverifiedChainSocket:
    def get_unverified_chain(self):
        return [LEAF, INTERMEDIATE]

    def getpeercert(self, binary_form=False):
        return LEAF


class LeafOnlySocket:
    def getpeercert(self, binary_form=False):
        return LEAF


class CertificateObject:
    """CPython 3.13 hands back Certificate objects, not raw bytes."""

    def __init__(self, der: bytes) -> None:
        self._der = der

    def public_bytes(self, *_args, **_kwargs) -> bytes:
        return self._der


class ObjectChainSocket:
    def get_verified_chain(self):
        return [CertificateObject(LEAF), CertificateObject(INTERMEDIATE)]

    def getpeercert(self, binary_form=False):
        return LEAF


class ExtractPeerChainTests(unittest.TestCase):
    def test_normalizes_certificate_objects_to_der_bytes(self) -> None:
        chain, source = main.extract_peer_chain(ObjectChainSocket())

        self.assertEqual(chain, [LEAF, INTERMEDIATE])
        self.assertEqual(source, "verified")

    def test_prefers_the_verified_chain_when_available(self) -> None:
        chain, source = main.extract_peer_chain(VerifiedChainSocket())

        self.assertEqual(chain, [LEAF, INTERMEDIATE, ROOT])
        self.assertEqual(source, "verified")

    def test_falls_back_to_the_unverified_chain(self) -> None:
        chain, source = main.extract_peer_chain(UnverifiedChainSocket())

        self.assertEqual(chain, [LEAF, INTERMEDIATE])
        self.assertEqual(source, "unverified")

    def test_reports_leaf_only_when_the_runtime_exposes_no_chain_api(self) -> None:
        """Python < 3.13 cannot read the chain; the report must say so, not pretend."""
        chain, source = main.extract_peer_chain(LeafOnlySocket())

        self.assertEqual(chain, [LEAF])
        self.assertEqual(source, "leaf-only")


if __name__ == "__main__":
    unittest.main()
