import importlib.util
from pathlib import Path


def parser():
    path = Path(__file__).parents[1] / "deploy/preflight/awg_packet_observer.py"
    spec = importlib.util.spec_from_file_location("awg_packet_observer", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.parse_packet


def test_only_scoped_udp_metadata_is_parsed():
    parse = parser()
    assert parse("1789000000.123 IP 192.0.2.1.54321 > 88.218.94.3.585: UDP, length 180") == (
        "incoming",
        "192.0.2.1:54321",
        180,
    )
    assert parse("1789000001.123 IP 88.218.94.3.585 > 192.0.2.1.54321: UDP, length 124") == (
        "outgoing",
        "192.0.2.1:54321",
        124,
    )
    assert parse("1789000001.123 IP 192.0.2.1.54321 > 192.0.2.2.585: UDP, length 124") is None
    assert parse("1789000001.123 IP 192.0.2.1.54321 > 88.218.94.3.443: UDP, length 124") is None
    assert parse("arbitrary payload or log message") is None
