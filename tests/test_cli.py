import json
from pathlib import Path

from kenai_vpn_admin.cli.main import (
    print_terminal_qr,
    render_cascade_exit,
    render_cascade_ingress_base,
)


def test_terminal_qr_does_not_write_files(capsys) -> None:
    print_terminal_qr("otpauth://totp/Kenai:test?secret=ABCDEFGHIJKLMNOP&issuer=Kenai")
    output = capsys.readouterr().out
    assert "█" in output or "▀" in output or "▄" in output
    assert "ABCDEFGHIJKLMNOP" not in output


def test_render_complete_ingress_and_exit_configs(tmp_path: Path) -> None:
    ingress_spec = tmp_path / "ingress-spec.json"
    ingress_output = tmp_path / "ingress.json"
    ingress_spec.write_text(
        json.dumps(
            {
                "listen_port": 443,
                "reality_target": "www.example.ru:443",
                "reality_private_key": "private-key-placeholder",
                "server_names": ["www.example.ru"],
                "short_ids": ["01234567"],
            }
        ),
        encoding="utf-8",
    )
    assert render_cascade_ingress_base(ingress_spec, ingress_output, "WRITE") == 0
    assert (
        json.loads(ingress_output.read_text(encoding="utf-8"))["outbounds"][0]["protocol"]
        == "blackhole"
    )

    exit_spec = tmp_path / "exit-spec.json"
    exit_output = tmp_path / "exit.json"
    exit_spec.write_text(
        json.dumps(
            {
                "location_slug": "armenia",
                "listen_port": 443,
                "ingress_uuid": "11111111-1111-4111-8111-111111111111",
                "ingress_name": "ru-entry-1",
                "reality_private_key": "private-key-placeholder",
                "reality_target": "cdn.example.com:443",
                "server_names": ["cdn.example.com"],
                "short_ids": ["89abcdef"],
            }
        ),
        encoding="utf-8",
    )
    assert render_cascade_exit(exit_spec, exit_output, "WRITE") == 0
    reality = json.loads(exit_output.read_text(encoding="utf-8"))["inbounds"][0]["streamSettings"][
        "realitySettings"
    ]
    assert reality["target"] == "cdn.example.com:443"


def test_render_refuses_unknown_secret_spec_fields(tmp_path: Path) -> None:
    spec = tmp_path / "spec.json"
    spec.write_text(
        json.dumps(
            {
                "listen_port": 443,
                "reality_target": "www.example.ru:443",
                "reality_private_key": "private-key-placeholder",
                "server_names": ["www.example.ru"],
                "short_ids": ["01234567"],
                "shell": "do-not-run",
            }
        ),
        encoding="utf-8",
    )

    assert render_cascade_ingress_base(spec, tmp_path / "output.json", "WRITE") == 1
    assert not (tmp_path / "output.json").exists()
