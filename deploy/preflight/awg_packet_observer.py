"""Bounded, passive UDP585 observation. Export counts, never packets or addresses."""

import json
import os
import re
import select
import subprocess
import sys
import time
from pathlib import Path

PACKET = re.compile(
    r"^(\d+(?:\.\d+)?) IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > "
    r"(\d+\.\d+\.\d+\.\d+)\.(\d+): UDP, length (\d+)"
)


def parse_packet(line: str) -> tuple[str, str, int] | None:
    match = PACKET.match(line)
    if match is None:
        return None
    _, source, source_port, destination, destination_port, length = match.groups()
    if destination == "88.218.94.3" and destination_port == "585":
        return "incoming", f"{source}:{source_port}", int(length)
    if source == "88.218.94.3" and source_port == "585":
        return "outgoing", f"{destination}:{destination_port}", int(length)
    return None


def observe(report: Path) -> None:
    started = time.monotonic()
    flows: dict[str, int] = {}
    counts: dict[tuple[int, int, str, int], int] = {}
    result: dict[str, object] = {"status": "starting", "duration_seconds": 90}
    # The caller creates a unique root-owned directory, writable by root only.
    with report.open("x", encoding="utf-8") as output:
        process = subprocess.Popen(
            [
                "/usr/bin/tcpdump",
                "-i",
                "ens3",
                "-nn",
                "-tt",
                "-q",
                "-s",
                "64",
                "-l",
                "ip and udp port 585 and host 88.218.94.3",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            assert process.stdout is not None
            result["status"] = "observing"
            json.dump(result, output)
            output.flush()
            pending = b""
            while time.monotonic() - started < 90:
                if process.poll() is not None:
                    result["status"] = "capture_failed"
                    break
                ready, _, _ = select.select([process.stdout], [], [], 0.5)
                if not ready:
                    continue
                pending += os.read(process.stdout.fileno(), 4096)
                lines = pending.split(b"\n")
                pending = lines.pop()
                for line in lines:
                    parsed = parse_packet(line.decode("ascii", errors="replace"))
                    if parsed is None:
                        continue
                    direction, address, length = parsed
                    if address not in flows:
                        if len(flows) >= 128:
                            result["flow_limit_reached"] = True
                            continue
                        flows[address] = len(flows) + 1
                    bucket = int((time.monotonic() - started) // 5) * 5
                    key = (bucket, flows[address], direction, length)
                    if len(counts) >= 10000 and key not in counts:
                        result["sample_limit_reached"] = True
                        continue
                    counts[key] = counts.get(key, 0) + 1
            else:
                result["status"] = "complete"
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            assert process.stderr is not None
            capture_stats = process.stderr.read(65536).decode("ascii", errors="replace")
            dropped = re.search(r"(\d+) packets dropped by kernel", capture_stats)
            result["kernel_drops"] = int(dropped.group(1)) if dropped else None
            result["packets"] = [
                dict(second=second, flow=flow, direction=direction, udp_length=length, count=count)
                for (second, flow, direction, length), count in sorted(counts.items())
            ]
            result["total_incoming"] = sum(
                n for (_, _, d, _), n in counts.items() if d == "incoming"
            )
            result["total_outgoing"] = sum(
                n for (_, _, d, _), n in counts.items() if d == "outgoing"
            )
            output.seek(0)
            output.truncate()
            json.dump(result, output)
            output.flush()


if __name__ == "__main__":
    observe(Path(sys.argv[1]))
