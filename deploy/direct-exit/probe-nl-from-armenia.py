#!/usr/bin/env python3
"""One-shot isolated SOCKS probe; never modifies Armenia's VPN or OS proxy."""

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path


def main() -> None:
    armenia = json.loads(Path("/usr/local/etc/xray/config.json").read_text())
    active = next(item for item in armenia["inbounds"] if item.get("protocol") == "vless")
    client_id = active["settings"]["clients"][0]["id"]
    netherlands = json.loads(Path("/root/nl-public-20260926.json").read_text())
    config = {
        "log": {"loglevel": "error"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 18080,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": netherlands["address"],
                            "port": 443,
                            "users": [
                                {"id": client_id, "encryption": "none", "flow": "xtls-rprx-vision"}
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "raw",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": netherlands["server_name"],
                        "publicKey": netherlands["public_key"],
                        "shortId": netherlands["short_id"],
                        "fingerprint": "chrome",
                    },
                },
            }
        ],
    }
    fd, name = tempfile.mkstemp(prefix="kenai-nl-probe-", suffix=".json", dir="/tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(config, output)
        client = subprocess.Popen(
            ["/usr/local/bin/xray", "run", "-config", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(2)
            if client.poll() is not None:
                raise RuntimeError("Probe Xray did not start")
            response = subprocess.run(
                [
                    "curl",
                    "-4",
                    "-fsS",
                    "--max-time",
                    "12",
                    "--socks5-hostname",
                    "127.0.0.1:18080",
                    "https://www.cloudflare.com/cdn-cgi/trace",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            values = dict(
                line.split("=", 1) for line in response.stdout.splitlines() if "=" in line
            )
            print("vpn_test_country=" + values.get("loc", "unknown"))
            print(
                "vpn_test_exit_matches_nl="
                + str(values.get("ip") == netherlands["address"]).lower()
            )
        finally:
            client.terminate()
            client.wait(timeout=5)
    finally:
        Path(name).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
