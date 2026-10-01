#!/usr/bin/env bash
# Compare the issued Kenai client (.13 from its diagnostic) with the live AWG
# server. No changes, no configuration values or key material in output.
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
[[ $EUID == 0 ]] || { echo root_required; exit 1; }
set -a
. /etc/kenai-vpn/web.env
set +a
/opt/kenai-vpn/venv-20260913/bin/python - <<'PY'
import base64
import configparser
import hashlib
import json
import subprocess
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from sqlalchemy import select, text
from kenai_vpn_admin.config import Settings
from kenai_vpn_admin.infrastructure.crypto import FernetCipher
from kenai_vpn_admin.infrastructure.database import build_engine, build_session_factory
from kenai_vpn_admin.infrastructure.models import AmneziaWgCredentialModel

def run(*args):
    return subprocess.run(args, capture_output=True, text=True, check=True, timeout=10).stdout.strip()

try:
    runtime = run('/usr/local/bin/awg', 'showconf', 'awg0')
    interface = configparser.ConfigParser(interpolation=None)
    interface.read_string(runtime.split('[Peer]')[0])
    server = interface['Interface']
    server_public = run('/usr/local/bin/awg', 'show', 'awg0', 'public-key')
    dump = run('/usr/local/bin/awg', 'show', 'awg0', 'dump')
    peers = [line.split('\t') for line in dump.splitlines()[1:]]
    settings = Settings()
    cipher = FernetCipher(settings.encryption_key, settings.secret_key, allow_derived=False)
    engine = build_engine(settings)
    with build_session_factory(engine)() as session:
        session.execute(text('SET TRANSACTION READ ONLY'))
        records = session.scalars(select(AmneziaWgCredentialModel).where(
            AmneziaWgCredentialModel.tunnel_address.in_(['10.67.67.13', '10.67.67.13/32'])
        )).all()
        print('matching_profiles=' + str(len(records)))
        for record in records:
            config = configparser.ConfigParser(interpolation=None)
            config.read_string(cipher.decrypt(record.encrypted_client_config))
            client, peer = config['Interface'], config['Peer']
            derived = X25519PrivateKey.from_private_bytes(base64.b64decode(client['PrivateKey'])).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            public = base64.b64encode(derived).decode()
            live = next((p for p in peers if p[0] == public), None)
            fields = ['s1','s2','s3','s4','h1','h2','h3','h4']
            mismatches = [name for name in fields if client.get(name, '0') != server.get(name, '0')]
            print(json.dumps(dict(
                status=record.status,
                server_key_matches=peer['PublicKey'] == server_public,
                client_key_matches_database=public == record.public_key,
                client_present_on_server=live is not None,
                server_allowed_address_matches=live is not None and '10.67.67.13/32' in live[3].split(','),
                endpoint_matches=peer['Endpoint'] == '88.218.94.3:' + server['ListenPort'],
                mismatched_transport_fields=mismatches,
                preshared_key_present=bool(peer.get('PresharedKey', '')),
                live_preshared_key_present=live is not None and live[1] != '(none)',
                s4_padding_enabled=int(client.get('s4', '0')) > 0,
                mismatched_junk_fields=[name for name in ['jc','jmin','jmax','i1','i2','i3','i4','i5'] if client.get(name, '') != server.get(name, '')],
                transport_fingerprint=hashlib.sha256('\n'.join(name+'='+client.get(name,'0') for name in fields).encode()).hexdigest(),
                client_public_fingerprint=hashlib.sha256(public.encode()).hexdigest(),
                server_public_fingerprint=hashlib.sha256(server_public.encode()).hexdigest(),
            )))
        session.rollback()
    engine.dispose()
except Exception as exc:
    # Suppress exception messages: SQL/config parse exceptions may contain secrets.
    print('profile_check_failed=' + type(exc).__name__)
    raise SystemExit(1)
PY
