import unittest

import main


class PartialWriteSink:
    """Mimics paramiko Channel/socket: send() may accept only part of the data."""

    MAX_PER_SEND = 10

    def __init__(self) -> None:
        self.received = bytearray()

    def send(self, data: bytes) -> int:
        chunk = data[: self.MAX_PER_SEND]
        self.received.extend(chunk)
        return len(chunk)

    def sendall(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            sent = self.send(view)
            view = view[sent:]


class ChunkedSource:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self._offset = 0

    def recv(self, size: int) -> bytes:
        chunk = self._payload[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk


class ForwardStreamTests(unittest.TestCase):
    def test_delivers_the_whole_chunk_despite_partial_writes(self) -> None:
        payload = b"x" * 4096  # a _nodes/stats response is far larger than one send()
        source = ChunkedSource(payload)
        sink = PartialWriteSink()

        while main.forward_stream(source, sink):
            pass

        self.assertEqual(bytes(sink.received), payload)

    def test_reports_end_of_stream_when_the_peer_closes(self) -> None:
        source = ChunkedSource(b"")
        sink = PartialWriteSink()

        self.assertFalse(main.forward_stream(source, sink))


if __name__ == "__main__":
    unittest.main()
