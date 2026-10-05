#!/usr/bin/env python3
"""Offline tests: no live exit nodes, routes, services or credentials touched."""
import ast
import hashlib
import json
import os
import socket
from pathlib import Path
import subprocess
import tarfile
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'bin/egress'
SOURCE = APP.read_text()
FUNCTIONS = SOURCE.split('# 只供受限 systemd 服务使用', 1)[0]
VERSION = '0.1.3'
PROXY_SOURCE = SOURCE.split("<<'PY'\n",1)[1].split('\nPY\n',1)[0]

def run(args, **kwargs):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=20, **kwargs)

def bash(body, *arguments):
    return run(['bash', '-c', FUNCTIONS + '\n' + body, '--', *map(str, arguments)])

class ApplicationTests(unittest.TestCase):
    def test_shell_syntax(self):
        for file in (APP, ROOT/'install.sh', ROOT/'scripts/build.sh'):
            with self.subTest(file=file.name):
                self.assertEqual(run(['bash', '-n', str(file)]).returncode, 0)

    def test_version_without_privileges(self):
        r=run(['bash',str(APP),'--version'])
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(r.stdout, f'OneEgress {VERSION}\n')

    def test_embedded_proxy_syntax(self):
        python=SOURCE.split("<<'PY'\n",1)[1].split('\nPY\n',1)[0]
        ast.parse(python)
        self.assertIn('socket.SO_BINDTODEVICE',python)
        self.assertIn('candidate.close()',python)

    def test_no_machine_identity_in_sources(self):
        self.assertNotRegex(SOURCE.replace("'100.64.0.0/10'", "'CGNAT_RANGE'"),r'\b100\.(?:[6-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b')
        self.assertNotRegex(SOURCE,r'tail[a-f0-9]+\.ts\.net|[\w.+-]+@gmail\.com')
        for artifact in ROOT.rglob('*'):
            if '.git' in artifact.parts or 'dist' in artifact.parts:
                continue
            self.assertNotIn(artifact.suffix,('.state','.key','.pem'))

    def test_empty_template_and_first_node(self):
        with tempfile.TemporaryDirectory(prefix='oneegress-config-') as temp:
            config=Path(temp)/'config.json'
            config.write_text((ROOT/'config.example.json').read_text())
            r=bash('CONFIG_FILE="$1"; DIR=$(dirname "$1"); load_configuration >/dev/null; cmd_config node phone-test 100.64.0.42',config)
            self.assertEqual(r.returncode,0,r.stderr)
            value=json.loads(config.read_text())
            self.assertEqual(value['default_node'],'phone-test')
            self.assertEqual(value['nodes'],{'phone-test':'100.64.0.42'})
            self.assertEqual(config.stat().st_mode&0o777,0o600)
            r=bash('CONFIG_FILE="$1"; DIR=$(dirname "$1"); cmd_config node ipad-test 100.64.0.43',config)
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertEqual(json.loads(config.read_text())['default_node'],'phone-test')

    def test_invalid_configuration_rejected(self):
        for value in ({'version':1,'default_node':'','default_user':'ubuntu','nodes':{'a':'129.1.1.1'}},
                      {'version':1,'default_node':'missing','default_user':'ubuntu','nodes':{}},
                      {'version':1,'default_node':'a','default_user':'bad user','nodes':{'a':'100.64.0.42'}}):
            r=bash('validate_configuration "$1"',json.dumps(value))
            self.assertEqual(r.returncode,2)

    def test_empty_switch_does_not_start_services(self):
        r=bash("""load_configuration() { echo '{"version":1,"default_node":"","default_user":"ubuntu","nodes":{}}'; }; """
               'proxy_up() { echo UNEXPECTED_START; return 99; }; cmd_switch')
        self.assertEqual(r.returncode,2)
        self.assertNotIn('UNEXPECTED_START',r.stdout)

    def test_shell_does_not_select_exit(self):
        r=bash("""load_configuration() { echo '{"default_user":"ubuntu"}'; }; """
               'shell_account() { return 0; }; cmd_check() { return 0; }; '
               'control_unlock() { echo UNLOCKED; }; '
               'run_work_shell() { echo "SHELL:$1"; }; '
               'proxy_up() { echo UNEXPECTED_START; return 99; }; '
               'pick_exit() { echo UNEXPECTED_PICK; return 99; }; cmd_shell ubuntu')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('UNLOCKED',r.stdout)
        self.assertIn('SHELL:ubuntu',r.stdout)
        self.assertNotIn('UNEXPECTED',r.stdout)

    def test_legacy_enter_does_not_select_exit(self):
        r=bash('cmd_shell() { echo "SHARED:$1"; }; '
               'pick_exit() { echo UNEXPECTED_PICK; return 99; }; cmd_enter')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('SHARED:root',r.stdout)
        self.assertNotIn('UNEXPECTED',r.stdout)

    def test_work_shell_guard(self):
        for command in ('switch', 'reload', 'repair', 'test'):
            r=bash('EGRESS_WORK_SHELL=1; guard_work_context "$1"', command)
            self.assertEqual(r.returncode,2)

    def test_reload_only_restarts_shared_proxy(self):
        with tempfile.TemporaryDirectory(prefix='oneegress-reload-') as temp:
            sock=Path(temp)/'local.sock'
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(sock))
                r=bash('SOCK="$1"; assert_host_route() { :; }; svc() { return 0; }; '
                       'hard_guard_ok() { return 0; }; service_dns_ok() { return 0; }; proxy_listening() { return 0; }; '
                       'systemctl() { echo "CALL:$*"; }; cmd_check() { echo CHECKED; return 0; }; '
                       'proxy_up() { echo UNEXPECTED; }; ts() { echo UNEXPECTED; }; cmd_reload',sock)
                self.assertEqual(r.returncode,0,r.stderr)
                self.assertIn('CALL:restart egress-socks',r.stdout)
                self.assertIn('CHECKED',r.stdout)
                self.assertNotIn('UNEXPECTED',r.stdout)
                self.assertNotIn('restart ts-egress',r.stdout)
                r=bash('SOCK="$1"; assert_host_route() { :; }; svc() { return 0; }; '
                       'hard_guard_ok() { return 1; }; systemctl() { echo UNEXPECTED; }; cmd_reload',sock)
                self.assertEqual(r.returncode,1,r.stderr)
                self.assertNotIn('UNEXPECTED',r.stdout)

    def test_reload_requires_existing_service_and_no_exit_argument(self):
        r=bash('assert_host_route() { :; }; svc() { return 1; }; systemctl() { echo UNEXPECTED; }; cmd_reload')
        self.assertEqual(r.returncode,2)
        self.assertNotIn('UNEXPECTED',r.stdout)
        r=bash('assert_host_route() { echo UNEXPECTED; }; cmd_reload ipad')
        self.assertEqual(r.returncode,2)
        self.assertNotIn('UNEXPECTED',r.stdout)

    def test_http_environment_is_global(self):
        # Both launch paths must use HTTP for HTTP(S), while ALL_PROXY keeps SOCKS compatibility.
        self.assertIn('export HTTPS_PROXY="http://10.200.0.1:1055"', SOURCE)
        self.assertIn('HTTPS_PROXY="http://$PROXY" https_proxy="http://$PROXY"', SOURCE)
        self.assertNotIn('HTTPS_PROXY="socks5h:', SOURCE)
        self.assertIn('ALL_PROXY="socks5h://$PROXY"', SOURCE)

    def test_check_verifies_both_protocols(self):
        self.assertIn('--proxy "http://$PROXY" https://ifconfig.me', SOURCE)
        self.assertIn('--socks5-hostname "$PROXY" https://ifconfig.me', SOURCE)
        self.assertIn('HTTP/CONNECT 未确认公网出口', SOURCE)

    def mocked_probe(self, responses):
        with tempfile.TemporaryDirectory(prefix='oneegress-probe-') as temp:
            log=Path(temp)/'calls'
            outcomes=json.dumps(responses)
            body='''
probe_log=$1
outcomes=$2
ip() {
  printf '%s\\n' "$*" >> "$probe_log"
  local index count rc
  count=$(wc -l < "$probe_log")
  index=$((count - 1))
  rc=$(jq -r --argjson i "$index" '.[$i][0] // 99' <<< "$outcomes")
  jq -r --argjson i "$index" '.[$i][1] // "unexpected extra attempt"' <<< "$outcomes"
  return "$rc"
}
probe_public test-probe --proxy http://10.200.0.1:1055 https://ifconfig.me
'''
            result=bash(body,log,outcomes)
            calls=log.read_text().splitlines()
            return result,calls

    def test_probe_success_uses_15_20_limits_once(self):
        r,calls=self.mocked_probe([[0,'203.0.113.42']])
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(r.stdout,'203.0.113.42\n')
        self.assertEqual(len(calls),1)
        self.assertIn('netns exec work curl -q -4 -fsS --connect-timeout 15 --max-time 20',calls[0])
        self.assertIn('--proxy http://10.200.0.1:1055 https://ifconfig.me',calls[0])
        self.assertEqual(r.stderr,'')

    def test_probe_timeout_retries_once_and_discards_partial_response(self):
        r,calls=self.mocked_probe([[28,'partial response\ncurl timeout'],[0,'203.0.113.42']])
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(r.stdout,'203.0.113.42\n')
        self.assertEqual(len(calls),2)
        self.assertEqual(calls[0],calls[1])
        self.assertIn('2/2',r.stderr)
        self.assertNotIn('partial',r.stdout)

    def test_probe_two_timeouts_fail_without_third_attempt(self):
        r,calls=self.mocked_probe([[28,'first timeout'],[28,'second timeout'],[0,'unreachable success']])
        self.assertEqual(r.returncode,28,r.stderr)
        self.assertEqual(len(calls),2)
        self.assertEqual(r.stdout,'second timeout\n')
        self.assertEqual(r.stderr.count('2/2'),1)

    def test_probe_non_timeout_errors_never_retry(self):
        for rc in (5,6,7,22,35,56,60,97):
            with self.subTest(rc=rc):
                r,calls=self.mocked_probe([[rc,'first failure'],[0,'unreachable success']])
                self.assertEqual(r.returncode,rc,r.stderr)
                self.assertEqual(len(calls),1)
                self.assertEqual(r.stdout,'first failure\n')
                self.assertEqual(r.stderr,'')

    def test_probe_retry_then_other_failure_preserves_final_error(self):
        r,calls=self.mocked_probe([[28,'timeout'],[60,'certificate failure'],[0,'unreachable success']])
        self.assertEqual(r.returncode,60,r.stderr)
        self.assertEqual(len(calls),2)
        self.assertEqual(r.stdout,'certificate failure\n')

    def test_probe_invalid_success_is_not_retried(self):
        r,calls=self.mocked_probe([[0,'invalid public response'],[0,'unreachable success']])
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(len(calls),1)
        self.assertEqual(r.stdout,'invalid public response\n')

    def mocked_check(self, override=''):
        body='''
SOCK=$1
load_configuration() { echo '{"default_node":"test","default_user":"ubuntu"}'; }
default_dev() { echo eth0; }
host_boundary_ok() { return 0; }
service_dns_ok() { return 0; }
host_ip() { echo 198.51.100.10; }
systemctl() {
  if [[ $1 == is-enabled ]]; then echo masked
  elif [[ $2 == tailscaled ]]; then echo inactive
  else echo active; fi
}
ts() { echo '{"BackendState":"Running","ExitNodeStatus":{"ID":"test"},"Peer":{"test":{"ID":"test","HostName":"test","Online":true,"ExitNode":true,"ExitNodeOption":true,"TailscaleIPs":["100.64.0.42"]}}}'; }
ip() {
  if [[ $* == 'netns list' ]]; then echo work
  elif [[ $* == *'route get'* ]]; then return 1
  elif [[ $* == *'curl'* ]]; then return 7
  fi
}
iptables() { return 0; }
hard_guard_ok() { return 0; }
proxy_listening() { return 0; }
probe_public() {
  if [[ $1 == 'ipinfo.io / SOCKS' ]]; then echo '{"ip":"203.0.113.42","country":"TEST","org":"AS64500 Test Provider"}'
  else echo 203.0.113.42; fi
}
'''+override+'\ncmd_check'
        with tempfile.TemporaryDirectory(prefix='oneegress-check-') as temp:
            sock=Path(temp)/'local.sock'
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(sock))
                return bash(body,sock)

    def test_check_admission_gates_preserved(self):
        r=self.mocked_check()
        self.assertEqual(r.returncode,0,r.stderr)
        for override in (
            'iptables() { return 1; }',
            'hard_guard_ok() { return 1; }',
            'host_ip() { echo 203.0.113.42; }',
            'host_boundary_ok() { return 1; }',
            'service_dns_ok() { return 1; }',
        ):
            with self.subTest(override=override):
                r=self.mocked_check(override)
                self.assertEqual(r.returncode,1,r.stdout+r.stderr)
                self.assertNotIn('当前出口已确认',r.stdout)

    def test_check_invalid_or_failed_probe_cannot_confirm_exit(self):
        for override in (
            'probe_public() { echo invalid; return 0; }',
            'probe_public() { echo timeout; return 28; }',
            'probe_public() { echo proxy_error; return 97; }',
        ):
            with self.subTest(override=override):
                r=self.mocked_check(override)
                self.assertEqual(r.returncode,2,r.stdout+r.stderr)
                self.assertNotIn('当前出口已确认',r.stdout)

    def test_init_preserves_existing_service(self):
        with tempfile.TemporaryDirectory(prefix='oneegress-init-') as temp:
            sock=Path(temp)/'local.sock'
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(sock))
                r=bash('SOCK="$1"; assert_host_route() { :; }; svc() { return 0; }; '
                       'ns_up() { echo UNEXPECTED_NS; return 99; }; '
                       'proxy_up() { echo UNEXPECTED_PROXY; return 99; }; cmd_init',sock)
                self.assertEqual(r.returncode,0,r.stderr)
                self.assertNotIn('UNEXPECTED',r.stdout)
                self.assertIn('未重启、未切换',r.stdout)

    def test_init_cannot_choose_an_exit(self):
        r=bash('assert_host_route() { echo UNEXPECTED; }; cmd_init ipad')
        self.assertEqual(r.returncode,2)
        self.assertNotIn('UNEXPECTED',r.stdout)

    def test_global_lock_contention(self):
        with tempfile.TemporaryDirectory(prefix='oneegress-lock-') as temp:
            lock=Path(temp)/'control.lock'
            # Override setup commands to avoid touching the real /run directory in this unit test.
            mocked=FUNCTIONS+'\nmkdir() { :; }; chmod() { :; };\n'+(
                'CONTROL_LOCK="$1"; control_lock; '
                'if (CONTROL_FD=; control_lock); then exit 99; else [[ $? == 75 ]] || exit 98; fi; '
                'control_unlock; (CONTROL_FD=; control_lock)')
            r=run(['bash','-c',mocked,'--',str(lock)])
            self.assertEqual(r.returncode,0,r.stderr)

class InstallerTests(unittest.TestCase):
    def test_staged_install_and_upgrade_preserve_state(self):
        with tempfile.TemporaryDirectory(prefix='oneegress-install-') as temp:
            args=['bash',str(ROOT/'install.sh'),'--destdir',temp,'--user','test_user']
            r=run(args+['--check'])
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertEqual(list(Path(temp).iterdir()),[])
            r=run(args)
            self.assertEqual(r.returncode,0,r.stderr)
            config=Path(temp)/'var/lib/tailscale-egress/config.json'
            program=Path(temp)/'usr/local/sbin/egress'
            self.assertEqual(json.loads(config.read_text())['default_user'],'test_user')
            self.assertEqual(program.read_bytes(),APP.read_bytes())
            self.assertEqual(program.stat().st_mode&0o777,0o755)
            self.assertEqual(config.stat().st_mode&0o777,0o600)
            config.write_text(json.dumps({'version':1,'default_node':'test','default_user':'test_user',
                                          'nodes':{'test':'100.64.0.42'}}))
            auth=config.parent/'tailscaled.state'
            auth.write_text('test state, not a credential')
            before=config.read_bytes()
            r=run(args)
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertEqual(config.read_bytes(),before)
            self.assertEqual(auth.read_text(),'test state, not a credential')
            r=run(args+['--config',str(ROOT/'config.example.json')])
            self.assertNotEqual(r.returncode,0)
            self.assertEqual(config.read_bytes(),before)

    def test_unsafe_destination_and_work_context_rejected(self):
        self.assertNotEqual(run(['bash',str(ROOT/'install.sh'),'--destdir','/']).returncode,0)
        env=dict(os.environ,EGRESS_WORK_SHELL='1')
        with tempfile.TemporaryDirectory(prefix='oneegress-install-') as temp:
            r=run(['bash',str(ROOT/'install.sh'),'--destdir',temp],env=env)
            self.assertNotEqual(r.returncode,0)
            self.assertEqual(list(Path(temp).iterdir()),[])

    def test_package_checksum_and_reproducibility(self):
        with tempfile.TemporaryDirectory(prefix='oneegress-package-') as temp:
            r=run(['bash',str(ROOT/'scripts/build.sh'),temp])
            self.assertEqual(r.returncode,0,r.stderr)
            archive=Path(temp)/f'oneegress-v{VERSION}.tar.gz'
            before=hashlib.sha256(archive.read_bytes()).hexdigest()
            self.assertIn(before,(Path(temp)/'SHA256SUMS').read_text())
            with tarfile.open(archive) as package:
                files={m.name for m in package.getmembers() if m.isfile()}
                self.assertEqual(files,{f'oneegress-{VERSION}/'+f for f in (
                    'bin/egress','install.sh','config.example.json','README.md','CHANGELOG.md')})
            r=run(['bash',str(ROOT/'scripts/build.sh'),temp])
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(),before)

class BoundaryTests(unittest.TestCase):
    def host_check(self, routes4=None, routes6=None, prefs=None, state='active', lookup='eth0'):
        routes4 = routes4 if routes4 is not None else [
            {'dst':'default','dev':'eth0'}, {'dst':'100.64.0.42','dev':'tailscale0','table':52},
            {'dst':'10.66.0.0/24','dev':'wg0'}, {'dst':'172.18.0.0/16','dev':'docker0'}]
        prefs = prefs if prefs is not None else {'RouteAll':False,'ExitNodeID':'','ExitNodeIP':'','RelayServerPort':40000}
        return bash('''
fixture_routes4=$1; fixture_routes6=$2; fixture_prefs=$3; fixture_state=$4; fixture_lookup=$5
systemctl() { echo "$fixture_state"; }
tailscale() { [[ $* == '--socket=/run/tailscale/tailscaled.sock debug prefs' ]] || return 99; echo "$fixture_prefs"; }
ip() {
  if [[ $* == '-j -4 route show table all' ]]; then echo "$fixture_routes4"
  elif [[ $* == '-j -6 route show table all' ]]; then echo "$fixture_routes6"
  elif [[ $* == *'route get'* ]]; then printf '[{"dev":"%s"}]\\n' "$fixture_lookup"
  elif [[ $* == 'link show egress-uplink' ]]; then return 0
  else return 99; fi
}
host_boundary_ok
''',json.dumps(routes4),json.dumps(routes6 or []),json.dumps(prefs),state,lookup)

    def test_peer_relay_wg_docker_coexistence_allowed(self):
        r=self.host_check()
        self.assertEqual(r.returncode,0,r.stderr)

    def test_inactive_system_tailscale_does_not_require_masking(self):
        self.assertEqual(self.host_check(state='inactive',prefs={}).returncode,0)

    def test_host_exit_and_route_import_rejected(self):
        for key,value in (('RouteAll',True),('ExitNodeID','node-test'),('ExitNodeIP','100.64.0.42')):
            prefs={'RouteAll':False,'ExitNodeID':'','ExitNodeIP':'',key:value}
            self.assertNotEqual(self.host_check(prefs=prefs).returncode,0)

    def test_unknown_or_changing_system_service_rejected(self):
        for state in ('activating','deactivating','failed','unknown',''):
            self.assertNotEqual(self.host_check(state=state).returncode,0)
        self.assertNotEqual(self.host_check(prefs={}).returncode,0)

    def test_public_policy_route_and_split_defaults_rejected(self):
        for route in (
            {'dst':'default','dev':'tailscale0','table':52},
            {'dst':'0.0.0.0/1','dev':'wg0','table':100},
            {'dst':'128.0.0.0/1','dev':'wg0'},
            {'dst':'1.1.1.1/32','dev':'tailscale0'},
            {'dst':'8.8.8.0/24','dev':'docker0'},
        ):
            self.assertNotEqual(self.host_check(routes4=[{'dst':'default','dev':'eth0'},route]).returncode,0)
        self.assertNotEqual(self.host_check(routes4=[]).returncode,0)
        self.assertNotEqual(self.host_check(routes4=[{'dst':'default','dev':'eth0'},{'dst':'default','dev':'eth0'}]).returncode,0)

    def test_ipv6_policy_route_rejected(self):
        for dst in ('default','2000::/3','2606:4700:4700::1111/128'):
            self.assertNotEqual(self.host_check(routes6=[{'dst':dst,'dev':'tailscale0','table':52}]).returncode,0)
        self.assertEqual(self.host_check(routes6=[{'dst':'fd7a:115c:a1e0::/48','dev':'tailscale0','table':52}]).returncode,0)

    def test_actual_policy_lookup_must_use_management_interface(self):
        self.assertNotEqual(self.host_check(lookup='wg0').returncode,0)

    def test_dns_requires_private_directory_exact_files_and_no_symlinks(self):
        with tempfile.TemporaryDirectory(prefix='oneegress-dns-') as temp:
            etc=Path(temp)/'etc'; etc.mkdir()
            resolv=etc/'resolv.conf'; nss=etc/'nsswitch.conf'
            resolv.write_text('nameserver 1.1.1.1\nnameserver 8.8.8.8\noptions timeout:2 attempts:1\n')
            nss.write_text('passwd: files\ngroup: files\nshadow: files\nhosts: files dns\nnetworks: files\n')
            self.assertEqual(bash('stat() { echo tmpfs; }; private_dns_ok "$1"',temp).returncode,0)
            self.assertNotEqual(bash('stat() { echo ext2/ext3; }; private_dns_ok "$1"',temp).returncode,0)
            resolv.write_text('nameserver 127.0.0.53\n')
            self.assertNotEqual(bash('stat() { echo tmpfs; }; private_dns_ok "$1"',temp).returncode,0)
            resolv.unlink(); resolv.symlink_to('missing')
            self.assertNotEqual(bash('stat() { echo tmpfs; }; private_dns_ok "$1"',temp).returncode,0)

    def test_dns_rejects_host_resolver_nss_module(self):
        with tempfile.TemporaryDirectory(prefix='oneegress-nss-') as temp:
            etc=Path(temp)/'etc'; etc.mkdir()
            (etc/'resolv.conf').write_text('nameserver 1.1.1.1\nnameserver 8.8.8.8\noptions timeout:2 attempts:1\n')
            (etc/'nsswitch.conf').write_text('hosts: files resolve dns\n')
            self.assertNotEqual(bash('stat() { echo tmpfs; }; private_dns_ok "$1"',temp).returncode,0)

    def test_all_daemon_launches_have_private_etc(self):
        self.assertIn('--property=TemporaryFileSystem=/etc:ro',SOURCE)
        self.assertNotIn('--property=BindReadOnlyPaths=/run/tailscale-egress/resolv.conf:/etc/resolv.conf',SOURCE)
        self.assertEqual(SOURCE.count('"${DNS_PROPERTIES[@]}"'),5)
        self.assertIn("private_dns_ok || die 'private proxy DNS boundary failed",SOURCE)

    def test_reload_refuses_bad_dns_without_restart(self):
        with tempfile.TemporaryDirectory(prefix='oneegress-dns-reload-') as temp:
            sock=Path(temp)/'socket'
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(sock))
                r=bash('SOCK="$1"; assert_host_route() { :; }; svc() { return 0; }; '
                       'hard_guard_ok() { return 0; }; service_dns_ok() { return 1; }; '
                       'systemctl() { echo UNEXPECTED; }; cmd_reload',sock)
                self.assertEqual(r.returncode,1,r.stderr)
                self.assertNotIn('UNEXPECTED',r.stdout)

    def repair(self, override=''):
        with tempfile.TemporaryDirectory(prefix='oneegress-repair-') as temp:
            sock=Path(temp)/'socket'
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(sock))
                return bash('''
SOCK=$1
assert_host_route() { :; }; host_boundary_ok() { return 0; }; svc() { return 0; }
hard_guard_ok() { return 0; }; service_dns_ok() { return 0; }; proxy_listening() { return 0; }
test_block_present() { return 1; }
selected_exit_state() { echo '[{"ID":"test","TailscaleIPs":["100.64.0.42"]}]'; }
ts() { [[ $* == 'debug prefs' ]] || { echo UNEXPECTED_SELECT; return 99; }; echo '{"CorpDNS":false,"NetfilterMode":0}'; }
systemctl() { echo "CALL:$*"; }; write_private_dns() { echo DNS_FILES; }; chmod() { :; }; sleep() { :; }
systemd-run() { echo START_TS; }; start_proxy() { echo START_PROXY; }; cmd_check() { echo CHECKED; }
ns_up() { echo UNEXPECTED_ROUTES; }; pick_exit() { echo UNEXPECTED_SELECT; }
'''+override+'\ncmd_repair',sock)

    def test_repair_retains_exit_and_does_not_rewrite_routes(self):
        r=self.repair()
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('CALL:stop egress-socks',r.stdout)
        self.assertLess(r.stdout.index('CALL:stop egress-socks'),r.stdout.index('CALL:stop ts-egress'))
        self.assertLess(r.stdout.index('START_TS'),r.stdout.index('START_PROXY'))
        self.assertNotIn('UNEXPECTED',r.stdout)
        self.assertIn('CHECKED',r.stdout)

    def test_repair_no_target_or_wrong_prefs_does_not_stop_services(self):
        for override in ('selected_exit_state() { return 1; }',
                         'ts() { echo "{}"; }', 'hard_guard_ok() { return 1; }'):
            r=self.repair(override)
            self.assertNotEqual(r.returncode,0)
            self.assertNotIn('CALL:stop',r.stdout)
            self.assertNotIn('START_PROXY',r.stdout)

    def test_repair_startup_failures_leave_proxy_stopped(self):
        for override in ('systemd-run() { return 1; }', 'service_dns_ok() { return 1; }'):
            r=self.repair(override)
            self.assertNotEqual(r.returncode,0)
            self.assertIn('CALL:stop egress-socks',r.stdout)
            self.assertNotIn('START_PROXY',r.stdout)
            self.assertNotIn('UNEXPECTED',r.stdout)

    def test_repair_cleans_its_own_test_rule_only_after_proxy_stopped(self):
        r=self.repair('test_block_present() { return 0; }; clear_test_block() { echo CLEAN_TEST_RULE; }')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertLess(r.stdout.index('CALL:stop egress-socks'),r.stdout.index('CLEAN_TEST_RULE'))
        self.assertLess(r.stdout.index('CLEAN_TEST_RULE'),r.stdout.index('START_PROXY'))

    def test_repair_rejects_exit_change_before_proxy_restart(self):
        r=self.repair('selected_exit_state() { if [[ ! -e $SOCK.changed ]]; then touch "$SOCK.changed"; echo first; else echo changed; fi; }')
        self.assertNotEqual(r.returncode,0)
        self.assertNotIn('START_PROXY',r.stdout)

    def test_repair_rejects_device_argument(self):
        r=bash('assert_host_route() { echo UNEXPECTED; }; cmd_repair ipad')
        self.assertEqual(r.returncode,2)
        self.assertNotIn('UNEXPECTED',r.stdout)

    def fault_test(self, override=''):
        return bash('''
exec 3>&1
cmd_check() { echo CHECKED; }
selected_exit_state() { echo same; }
host_boundary_ok() { return 0; }; hard_guard_ok() { return 0; }; service_dns_ok() { return 0; }
clear_test_block() { echo RESTORED >&3; }
router() {
  if [[ $* == *'-I EGRESS_PROXY 1'* ]]; then echo BLOCKED
  else echo UNEXPECTED; return 99; fi
}
ip() { return 7; }
ts() { echo UNEXPECTED_SELECT; return 99; }
'''+override+'\ncmd_test')

    def test_fault_test_restores_guard_and_verifies_same_exit(self):
        r=self.fault_test()
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(r.stdout.count('CHECKED'),2)
        self.assertEqual(r.stdout.splitlines().count('RESTORED'),1)
        self.assertIn('socks；curl=7',r.stdout)
        self.assertIn('http；curl=7',r.stdout)
        self.assertNotIn('UNEXPECTED',r.stdout)

    def test_fault_test_unexpected_connectivity_fails_and_restores(self):
        r=self.fault_test('ip() { return 0; }')
        self.assertEqual(r.returncode,1,r.stderr)
        self.assertEqual(r.stdout.splitlines().count('RESTORED'),1)
        self.assertEqual(r.stdout.count('CHECKED'),1)

    def test_fault_test_sigterm_restores_guard(self):
        r=self.fault_test('ip() { kill -TERM "$BASHPID"; return 7; }')
        self.assertEqual(r.returncode,143,r.stderr)
        self.assertEqual(r.stdout.splitlines().count('RESTORED'),1)

    def test_fault_test_bad_precheck_does_not_change_guard(self):
        r=self.fault_test('cmd_check() { return 1; }')
        self.assertEqual(r.returncode,1)
        self.assertNotIn('BLOCKED',r.stdout)

    def test_legacy_automatic_device_fallback_removed(self):
        self.assertNotIn('pick_exit() {',SOURCE)
        self.assertNotIn('use_node() {',SOURCE)
        self.assertIn('up|start) shift; cmd_switch "$@"',SOURCE)
        self.assertNotIn('prefer == home',SOURCE)

class ProxyTests(unittest.TestCase):
    def setUp(self):
        self.proxy = {'__name__': 'oneegress_proxy_test', 'TUN': 'test-tun'}
        exec(compile(PROXY_SOURCE, 'embedded_proxy', 'exec'), self.proxy)

    def conversation(self, payload, connect, followup=b''):
        client, service = socket.socketpair()
        client.settimeout(3)
        self.proxy['tunnel_connect'] = connect
        worker = threading.Thread(target=self.proxy['Handler'], args=(service, ('test', 0), None), daemon=True)
        worker.start()
        try:
            client.sendall(payload)
            first = client.recv(65536)
            if followup:
                client.sendall(followup)
                first += client.recv(65536)
            return first
        finally:
            client.close()
            worker.join(3)
            service.close()
            self.assertFalse(worker.is_alive(), 'proxy worker did not exit')

    def failed_connect(self, *args):
        raise ConnectionError('simulated exit offline')

    def test_http_connect_failure_returns_502_not_success(self):
        response=self.conversation(b'CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n', self.failed_connect)
        self.assertTrue(response.startswith(b'HTTP/1.1 502'), response)
        self.assertNotIn(b'200', response)

    def test_http_forward_failure_returns_502(self):
        response=self.conversation(b'GET http://example.com/test HTTP/1.1\r\nHost: example.com\r\n\r\n', self.failed_connect)
        self.assertTrue(response.startswith(b'HTTP/1.1 502'), response)

    def test_invalid_http_never_attempts_connect(self):
        for request in (
            b'GET /relative HTTP/1.1\r\nHost: example.com\r\n\r\n',
            b'CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n',
            b'CONNECT localhost:0 HTTP/1.1\r\nHost: localhost\r\n\r\n',
            b'GET http://user:password@example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n',
            b'GET http://example.com/ HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n',
            b'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n',
            b'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: Content-Length\r\n\r\n',
            b'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n folded: header\r\n\r\n',
            b'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX-Long: '+b'a'*17000+b'\r\n\r\n',
        ):
            with self.subTest(request=request[:100]):
                connector=mock.Mock(side_effect=AssertionError('unexpected outbound connection'))
                response=self.conversation(request, connector)
                self.assertTrue(response.startswith(b'HTTP/1.1 400'), response)
                connector.assert_not_called()

    def test_http_forward_rewrites_target_and_strips_proxy_credentials(self):
        class Client:
            def settimeout(self, timeout): pass
            def recv(self, size):
                data=self.data[:size]
                self.data=self.data[size:]
                return data
        client=Client()
        client.data=b'OST http://example.com:8080/path?q=1 HTTP/1.1\r\nHost: ignored\r\nProxy-Authorization: secret\r\nProxy-Connection: keep-alive\r\nContent-Length: 4\r\n\r\nbody'
        host, port, family, method, forward, pending=self.proxy['http_request'](client,b'P')
        self.assertEqual((host,port,method),('example.com',8080,'POST'))
        self.assertTrue(forward.startswith(b'POST /path?q=1 HTTP/1.1\r\n'))
        self.assertIn(b'Host: example.com:8080\r\n',forward)
        self.assertIn(b'Connection: close\r\n',forward)
        self.assertNotIn(b'secret',forward)
        self.assertNotIn(b'ignored',forward)
        self.assertEqual(pending,b'body')

    def test_connect_relays_without_tls_interception(self):
        outbound, upstream=socket.socketpair()
        upstream.settimeout(3)
        seen=[]
        def echo():
            try:
                seen.append(upstream.recv(65536))
                upstream.sendall(b'opaque-server-data')
            finally:
                upstream.close()
        worker=threading.Thread(target=echo, daemon=True)
        worker.start()
        connector=mock.Mock(return_value=outbound)
        response=self.conversation(b'CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n', connector, b'opaque-client-data')
        worker.join(3)
        self.assertEqual(response,b'HTTP/1.1 200 Connection Established\r\n\r\nopaque-server-data')
        self.assertEqual(seen,[b'opaque-client-data'])
        connector.assert_called_once_with('api.anthropic.com',443,socket.AF_INET)

    def test_socks_protocol_still_works_and_fails_closed(self):
        client, service=socket.socketpair()
        client.settimeout(3)
        self.proxy['tunnel_connect']=self.failed_connect
        worker=threading.Thread(target=self.proxy['Handler'],args=(service,('test',0),None),daemon=True)
        worker.start()
        try:
            client.sendall(b'\x05\x01\x00')
            self.assertEqual(client.recv(2),b'\x05\x00')
            client.sendall(b'\x05\x01\x00\x03\x0bexample.com\x01\xbb')
            self.assertEqual(client.recv(10),b'\x05\x04\x00\x01'+b'\x00'*6)
        finally:
            client.close()
            worker.join(3)
            service.close()
            self.assertFalse(worker.is_alive())

    def test_public_destinations_only(self):
        for address, af in (('127.0.0.1',socket.AF_INET),('10.200.0.1',socket.AF_INET),('169.254.169.254',socket.AF_INET),('::1',socket.AF_INET6),('fd00::1',socket.AF_INET6)):
            with self.subTest(address=address), mock.patch.object(socket,'getaddrinfo',return_value=[(af,socket.SOCK_STREAM,6,'',(address,443))]), mock.patch.object(socket,'socket') as factory:
                with self.assertRaises(ConnectionError):
                    self.proxy['tunnel_connect'](address,443,af)
                factory.assert_not_called()

    def test_missing_tunnel_never_retries_unbound(self):
        candidate=mock.Mock()
        candidate.setsockopt.side_effect=OSError('tunnel unavailable')
        with mock.patch.object(socket,'getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('1.1.1.1',443))]), mock.patch.object(socket,'socket',return_value=candidate) as factory:
            with self.assertRaises(ConnectionError):
                self.proxy['tunnel_connect']('one.one.one.one',443)
            factory.assert_called_once()
            candidate.setsockopt.assert_called_once_with(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'test-tun\0')
            candidate.connect.assert_not_called()
            candidate.close.assert_called_once()

    def test_failed_tunnel_connect_closes_socket_without_fallback(self):
        candidate=mock.Mock()
        candidate.connect.side_effect=OSError('exit offline')
        with mock.patch.object(socket,'getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('1.1.1.1',443))]), mock.patch.object(socket,'socket',return_value=candidate) as factory:
            with self.assertRaises(ConnectionError):
                self.proxy['tunnel_connect']('one.one.one.one',443)
            factory.assert_called_once()
            candidate.setsockopt.assert_called_once()
            candidate.connect.assert_called_once()
            candidate.close.assert_called_once()

if __name__=='__main__':
    unittest.main(verbosity=2)
