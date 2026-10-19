"""File: deployment/tests/test_executor_listener_procfs.py.

Purpose: Regression-test complete, size-bounded procfs Unix-socket inventory reads.
Related: deployment/executor_listener.py, deployment/tests/test_executor_listener.py.
All tests use inert streams or an isolated, temporary Unix socket. They never
connect to the privileged DEV socket, invoke deployment, or access replay.
"""

from __future__ import annotations

import io
import os
import socket
import tempfile
import unittest

from deployment import executor_listener


class _ShortReadStream(io.BytesIO):
    """Emulate a Linux seq_file short read even with a large requested size."""

    def __init__(self, content: bytes, *, chunk_size: int) -> None:
        super().__init__(content)
        self.chunk_size = chunk_size
        self.read_sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        """Return at most one kernel-sized chunk per unbuffered call."""

        result = super().read(min(size, self.chunk_size))
        self.read_sizes.append(len(result))
        return result


class ProcfsInventoryReadTests(unittest.TestCase):
    """Reject truncated inventories while accepting complete short-read streams."""

    def test_short_unbuffered_reads_continue_to_eof(self) -> None:
        """A short read must not be mistaken for EOF."""

        inventory = b"Num RefCount Protocol Flags Type St Inode Path\n" + b"abc123" * 20
        streams: list[_ShortReadStream] = []

        def opener(path: str, mode: str, *, buffering: int) -> _ShortReadStream:
            """Supply a partial-read stream with exact read-only parameters."""

            self.assertEqual((path, mode, buffering), ("/proc/self/net/unix", "rb", 0))
            stream = _ShortReadStream(inventory, chunk_size=7)
            streams.append(stream)
            return stream

        result = executor_listener._read_proc_unix(
            "/proc/self/net/unix", opener=opener, maximum=256,
        )
        self.assertEqual(result, inventory)
        self.assertEqual(len(streams), 1)
        self.assertGreater(len(streams[0].read_sizes), 2)
        self.assertEqual(streams[0].read_sizes[-1], 0)

    def test_exact_ceiling_allows_clean_eof(self) -> None:
        """Exactly the byte ceiling is valid when EOF follows."""

        stream = _ShortReadStream(b"12345678", chunk_size=3)

        def opener(_path: str, _mode: str, *, buffering: int) -> _ShortReadStream:
            """Return a bounded, cleanly terminating stream."""

            return stream

        self.assertEqual(
            executor_listener._read_proc_unix("inert", opener=opener, maximum=8),
            b"12345678",
        )

    def test_oversized_inventory_fails_closed(self) -> None:
        """Reject overflow even when every individual read is short."""

        def opener(_path: str, _mode: str, *, buffering: int) -> _ShortReadStream:
            """Supply one byte over the reviewed maximum."""

            return _ShortReadStream(b"12345678", chunk_size=2)

        with self.assertRaisesRegex(OSError, "^invalid Unix socket inventory$"):
            executor_listener._read_proc_unix("inert", opener=opener, maximum=7)

    def test_excessive_short_read_count_fails_closed(self) -> None:
        """Avoid unlimited syscalls for pathological one-byte streams."""

        def opener(_path: str, _mode: str, *, buffering: int) -> _ShortReadStream:
            """Supply enough data to hit the call limit before EOF."""

            return _ShortReadStream(b"x" * 2048, chunk_size=1)

        with self.assertRaisesRegex(OSError, "^invalid Unix socket inventory$"):
            executor_listener._read_proc_unix("inert", opener=opener, maximum=2048)

    def test_nonbyte_stream_rejected(self) -> None:
        """Invalid stream return values must never be normalized silently."""

        class WrongTypeStream(io.BytesIO):
            """Return a non-byte value after one valid read."""

            def read(self, size: int = -1) -> object:
                if self.tell() == 0:
                    return super().read(1)
                return "untrusted-marker"

        def opener(_path: str, _mode: str, *, buffering: int) -> WrongTypeStream:
            """Supply an invalid second stream read."""

            return WrongTypeStream(b"abc")

        with self.assertRaisesRegex(OSError, "^invalid Unix socket inventory$"):
            executor_listener._read_proc_unix("inert", opener=opener, maximum=128)

    @unittest.skipUnless(os.path.exists("/proc/self/net/unix"), "Linux-only")
    def test_full_live_procfs_snapshot_contains_inert_socket(self) -> None:
        """Verify the real procfs reader using only a fresh disposable socket."""

        with tempfile.TemporaryDirectory(prefix="task014-inert-listener-") as directory:
            path = os.path.join(directory, "socket")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(path)
                listener.listen(1)
                inventory = executor_listener._read_proc_unix("/proc/self/net/unix")
                self.assertIn(path.encode("ascii"), inventory)
                executor_listener._require_proc_binding(
                    inventory, os.fstat(listener.fileno()).st_ino, path,
                )


if __name__ == "__main__":
    unittest.main()
