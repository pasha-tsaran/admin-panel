#!/usr/bin/env bash
# Read-only network diagnostics. Never print profiles, private keys or peer keys.
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
[[ $EUID == 0 ]] || { echo root_required; exit 1; }
python3 - <<'PY'
import json
import shutil
import subprocess
import time

def run(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=10)
    if p.returncode:
        raise RuntimeError('command_failed:' + args[0])
    return p.stdout

awg = shutil.which('awg')
if not awg:
    raise SystemExit('awg_binary_missing')
dump = run([awg, 'show', 'awg0', 'dump']).splitlines()
print('awg_listen_port=' + dump[0].split('\t')[2])
print('ipv4_forward=' + open('/proc/sys/net/ipv4/ip_forward').read().strip())
for index, line in enumerate(dump[1:], 1):
    fields = line.split('\t')
    handshake = int(fields[4])
    print(json.dumps(dict(peer=index, address=fields[3], handshake_age_seconds=(int(time.time())-handshake if handshake else None), received=int(fields[5]), sent=int(fields[6]))))
print('--- IPv4 firewall, counters only; no VPN key material ---')
if shutil.which('iptables'):
    for table in ('filter', 'nat'):
        print('table=' + table)
        print(run(['iptables', '-t', table, '-L', '-n', '-v', '--line-numbers']))
elif shutil.which('nft'):
    print(run(['nft', 'list', 'ruleset']))
else:
    print('firewall_tools_unavailable')
def interface_values(text):
    values = {}
    for line in text.splitlines():
        if line.strip() == '[Peer]':
            break
        if '=' in line:
            name, value = line.split('=', 1)
            values[name.strip().lower()] = value.strip()
    return values
runtime = interface_values(run([awg, 'showconf', 'awg0']))
stored = interface_values(open('/etc/amneziawg/awg0.conf').read())
for name in ('PrivateKey', 'ListenPort', 'Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5'):
    key = name.lower()
    print('runtime_matches_file_' + name + '=' + str(runtime.get(key, '0') == stored.get(key, '0')))
print('--- AWG interface ---')
print(run(['ip', '-s', 'link', 'show', 'awg0']))
PY
