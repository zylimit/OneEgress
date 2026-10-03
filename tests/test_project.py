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
import unittest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'bin/egress'
SOURCE = APP.read_text()
FUNCTIONS = SOURCE.split('# 只供受限 systemd 服务使用', 1)[0]

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
        self.assertRegex(r.stdout, r'^OneEgress 0\.1\.0\n$')

    def test_embedded_proxy_syntax(self):
        python=SOURCE.split("<<'PY'\n",1)[1].split('\nPY\n',1)[0]
        ast.parse(python)
        self.assertIn('socket.SO_BINDTODEVICE',python)
        self.assertIn('candidate.close()',python)

    def test_no_machine_identity_in_sources(self):
        self.assertNotRegex(SOURCE,r'\b100\.(?:[6-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b')
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
        r=bash('EGRESS_WORK_SHELL=1; guard_work_context switch')
        self.assertEqual(r.returncode,2)

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
            archive=Path(temp)/'oneegress-v0.1.0.tar.gz'
            before=hashlib.sha256(archive.read_bytes()).hexdigest()
            self.assertIn(before,(Path(temp)/'SHA256SUMS').read_text())
            with tarfile.open(archive) as package:
                files={m.name for m in package.getmembers() if m.isfile()}
                self.assertEqual(files,{'oneegress-0.1.0/'+f for f in (
                    'bin/egress','install.sh','config.example.json','README.md','CHANGELOG.md')})
            r=run(['bash',str(ROOT/'scripts/build.sh'),temp])
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(),before)

if __name__=='__main__':
    unittest.main(verbosity=2)
