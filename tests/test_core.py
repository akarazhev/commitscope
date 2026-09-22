import base64
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sec_review.core import trusted_internal_temp_path
tempfile.tempdir = str(trusted_internal_temp_path(Path(tempfile.gettempdir())))

class CoreTests(unittest.TestCase):
    def test_json_duplicate_keys_rejected(self):
        from sec_review.core import decode_json, ReviewError
        with self.assertRaises(ReviewError): decode_json('{"a":1,"a":2}')
    def test_json_nonfinite_rejected(self):
        from sec_review.core import decode_json, ReviewError
        with self.assertRaises(ReviewError): decode_json('{"a":NaN}')
    def test_safe_paths(self):
        from sec_review.core import safe_path, ReviewError
        for path in ('../secret', '/etc/passwd', 'a/../b', 'a\\b', 'C:/x', 'a\nb', './x'):
            with self.subTest(path=path), self.assertRaises(ReviewError): safe_path(path)
        self.assertEqual(safe_path('src/main.py').as_posix(), 'src/main.py')
    def test_environment_does_not_leak_credentials(self):
        from sec_review.core import child_env
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {'ANTHROPIC_API_KEY':'secret','AWS_SECRET_ACCESS_KEY':'secret','SEMGREP_APP_TOKEN':'secret','PYTHONPATH':'/evil','GIT_CONFIG_COUNT':'1'}):
            e = child_env(Path(d))
            for key in ('ANTHROPIC_API_KEY','AWS_SECRET_ACCESS_KEY','SEMGREP_APP_TOKEN','PYTHONPATH','GIT_CONFIG_COUNT'):
                self.assertNotIn(key, e)
    def test_process_exit_code_and_stdout(self):
        from sec_review.core import execute, child_env
        with tempfile.TemporaryDirectory() as d:
            r = execute([sys.executable, '-I', '-c', 'print("ok");raise SystemExit(7)'], Path(d), child_env(Path(d)), 5)
            self.assertEqual(r.code, 7); self.assertEqual(r.stdout.strip(), 'ok'); self.assertFalse(r.timed_out)
    def test_timeout_is_not_success(self):
        from sec_review.core import execute, child_env
        with tempfile.TemporaryDirectory() as d:
            r = execute([sys.executable, '-I', '-c', 'import time;time.sleep(10)'], Path(d), child_env(Path(d)), .1)
            self.assertTrue(r.timed_out); self.assertNotEqual(r.code, 0)
    def test_shell_metacharacters_are_data(self):
        from sec_review.core import execute, child_env
        with tempfile.TemporaryDirectory() as d:
            r = execute([sys.executable, '-I', '-c', 'import sys;print(sys.argv[1])','x; touch owned'], Path(d), child_env(Path(d)), 5)
            self.assertIn('x; touch owned', r.stdout); self.assertFalse((Path(d)/'owned').exists())
    def test_write_refuses_symlink(self):
        from sec_review.core import write_json, ReviewError
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); (p/'real').write_text('keep'); (p/'link').symlink_to(p/'real')
            with self.assertRaises(ReviewError): write_json(p/'link', {'x':1})
            self.assertEqual((p/'real').read_text(), 'keep')
    def test_internal_temp_path_canonicalizes_system_alias(self):
        from sec_review.core import trusted_internal_temp_path
        with tempfile.TemporaryDirectory() as d, patch('sec_review.core.tempfile.gettempdir') as gettempdir:
            root=Path(d).resolve(); canonical=root/'private'/'var'; canonical.mkdir(parents=True)
            alias=root/'var'; alias.symlink_to(canonical,target_is_directory=True)
            gettempdir.return_value=str(alias)
            self.assertEqual(trusted_internal_temp_path(alias/'folders'/'case'), canonical/'folders'/'case')
    def test_user_path_symlink_parent_is_still_rejected(self):
        from sec_review.core import no_symlinks, ReviewError
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); real=root/'real'; real.mkdir()
            alias=root/'alias'; alias.symlink_to(real,target_is_directory=True)
            with self.assertRaises(ReviewError): no_symlinks(alias/'out')

class InstallerTests(unittest.TestCase):
    def semgrep_record(self, root, wrapper):
        digest=base64.urlsafe_b64encode(hashlib.sha256(wrapper.read_bytes()).digest()).decode().rstrip('=')
        record=root/'semgrep-env/lib/python3.14/site-packages/semgrep-1.177.0.dist-info/RECORD'
        record.parent.mkdir(parents=True,exist_ok=True)
        record.write_text(f'../../../bin/semgrep,sha256={digest},{wrapper.stat().st_size}\n')
    def archive(self, path, name, kind=tarfile.REGTYPE, data=b'binary', mode=0o755):
        with tarfile.open(path, 'w:gz') as t:
            info=tarfile.TarInfo(name); info.type=kind; info.size=len(data) if kind==tarfile.REGTYPE else 0
            info.mode=mode
            t.addfile(info, io.BytesIO(data) if kind==tarfile.REGTYPE else None)
    def archive_many(self, path, members):
        with tarfile.open(path, 'w:gz') as t:
            for member in members:
                name,kind,data=member[:3]; mode=member[3] if len(member)>3 else 0o644
                info=tarfile.TarInfo(name); info.type=kind; info.size=len(data) if kind==tarfile.REGTYPE else 0
                info.mode=mode
                t.addfile(info, io.BytesIO(data) if kind==tarfile.REGTYPE else None)
    def test_verified_binary_extraction(self):
        from sec_review.tools import extract_binary
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); self.archive(p/'a.tgz','gitleaks'); extract_binary(p/'a.tgz','gitleaks',p/'binary')
            self.assertEqual((p/'binary').read_bytes(),b'binary')
    def test_realistic_trivy_archive_extracts_exact_root_executable(self):
        from sec_review.tools import extract_binary
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            self.archive_many(p/'trivy.tgz',[
                ('LICENSE',tarfile.REGTYPE,b'license'),
                ('README.md',tarfile.REGTYPE,b'readme'),
                ('contrib/asff.tpl',tarfile.REGTYPE,b'template'),
                ('trivy',tarfile.REGTYPE,b'binary',0o755)])
            extract_binary(p/'trivy.tgz','trivy',p/'binary')
            self.assertEqual((p/'binary').read_bytes(),b'binary')
    def test_trivy_binary_limit_covers_pinned_linux_release_size(self):
        from sec_review.tools import MAX_BINARY_BYTES
        self.assertGreaterEqual(MAX_BINARY_BYTES,168456354)
    def test_archive_link_rejected(self):
        from sec_review.tools import extract_binary
        from sec_review.core import ReviewError
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); self.archive(p/'a.tgz','gitleaks',tarfile.SYMTYPE)
            with self.assertRaises(ReviewError): extract_binary(p/'a.tgz','gitleaks',p/'binary')
    def test_archive_traversal_not_extracted(self):
        from sec_review.tools import extract_binary
        from sec_review.core import ReviewError
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); self.archive(p/'a.tgz','../gitleaks')
            with self.assertRaises(ReviewError): extract_binary(p/'a.tgz','gitleaks',p/'binary')
    def test_archive_rejects_unsafe_non_executable_member(self):
        from sec_review.tools import extract_binary
        from sec_review.core import ReviewError
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); self.archive_many(p/'a.tgz',[('../README.md',tarfile.REGTYPE,b'x'),('gitleaks',tarfile.REGTYPE,b'binary')])
            with self.assertRaises(ReviewError): extract_binary(p/'a.tgz','gitleaks',p/'binary')
            self.assertFalse((p/'binary').exists())
    def test_archive_rejects_absolute_member(self):
        from sec_review.tools import extract_binary
        from sec_review.core import ReviewError
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); self.archive_many(p/'a.tgz',[('/tmp/README.md',tarfile.REGTYPE,b'x'),('gitleaks',tarfile.REGTYPE,b'binary')])
            with self.assertRaises(ReviewError): extract_binary(p/'a.tgz','gitleaks',p/'binary')
    def test_archive_rejects_duplicate_executables(self):
        from sec_review.tools import extract_binary
        from sec_review.core import ReviewError
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); self.archive_many(p/'a.tgz',[('gitleaks',tarfile.REGTYPE,b'one'),('./gitleaks',tarfile.REGTYPE,b'two')])
            with self.assertRaises(ReviewError): extract_binary(p/'a.tgz','gitleaks',p/'binary')
    def test_archive_hardlink_rejected(self):
        from sec_review.tools import extract_binary
        from sec_review.core import ReviewError
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); self.archive(p/'a.tgz','gitleaks',tarfile.LNKTYPE)
            with self.assertRaises(ReviewError): extract_binary(p/'a.tgz','gitleaks',p/'binary')
    def test_archive_non_executable_binary_rejected(self):
        from sec_review.tools import extract_binary
        from sec_review.core import ReviewError
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); self.archive(p/'a.tgz','gitleaks',mode=0o600)
            with self.assertRaises(ReviewError): extract_binary(p/'a.tgz','gitleaks',p/'binary')
    def test_archive_empty_binary_rejected(self):
        from sec_review.tools import extract_binary
        from sec_review.core import ReviewError
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); self.archive(p/'a.tgz','gitleaks',data=b'',mode=0o755)
            with self.assertRaises(ReviewError): extract_binary(p/'a.tgz','gitleaks',p/'binary')
    def test_bad_hash_rejected_before_use(self):
        from sec_review.tools import verify_hash
        from sec_review.core import ReviewError
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'file'; p.write_bytes(b'not the binary')
            with self.assertRaises(ReviewError): verify_hash(p,'0'*64)
    def test_platform_selection(self):
        from sec_review.tools import platform_key
        from sec_review.core import ReviewError
        self.assertEqual(platform_key('Linux','x86_64'),'linux-x86_64')
        self.assertEqual(platform_key('Linux','aarch64'),'linux-arm64')
        self.assertEqual(platform_key('Darwin','AMD64'),'darwin-x86_64')
        self.assertEqual(platform_key('Darwin','arm64'),'darwin-arm64')
        with self.assertRaises(ReviewError): platform_key('Windows','AMD64')
    def test_pins_are_complete(self):
        from sec_review.tools import lock
        l=lock()
        for tool in ('gitleaks','trivy','semgrep'):
            for platform in ('linux-x86_64','linux-arm64','darwin-x86_64','darwin-arm64'):
                entry=l['tools'][tool]['assets'][platform]
                self.assertRegex(entry['sha256'],r'^[0-9a-f]{64}$')
                self.assertTrue(entry['url'].startswith('https://'))
    def test_tool_lock_can_be_read_from_selected_resources(self):
        from sec_review.tools import lock
        with tempfile.TemporaryDirectory() as directory:
            resources = Path(directory).resolve()
            config = resources / 'config'
            config.mkdir()
            (config / 'tools.lock.json').write_text('{"schema_version":"selected","tools":{}}')
            self.assertEqual(lock(resources)['schema_version'], 'selected')
    def test_semgrep_doctor_uses_package_and_core_versions_when_wrapper_is_stale(self):
        from sec_review.tools import inspect_tools
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for tool,body in {
                'bin/gitleaks':'#!/bin/sh\necho 8.30.1\n',
                'bin/trivy':'#!/bin/sh\necho Version: 0.74.0\n',
                'semgrep-env/bin/python':'#!/bin/sh\necho 1.177.0\n',
                'semgrep-env/bin/semgrep':'#!/bin/sh\ntest -n "$SSL_CERT_FILE" || exit 9\necho 1.172.0\n',
                'semgrep-env/lib/python3.14/site-packages/semgrep/bin/semgrep-core':'#!/bin/sh\necho semgrep-core version: 1.177.0\n',
            }.items():
                p=root/tool; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(body); p.chmod(0o700)
            cert=root/'semgrep-env/lib/python3.14/site-packages/certifi/cacert.pem'
            cert.parent.mkdir(parents=True); cert.write_text('certs')
            self.semgrep_record(root,root/'semgrep-env/bin/semgrep')
            result=inspect_tools(root)
            self.assertTrue(result['semgrep']['ok'],result['semgrep'])
            self.assertIn('cli: 1.172.0',result['semgrep']['reported'])
    def test_semgrep_doctor_rejects_wrapper_changed_after_install(self):
        from sec_review.tools import inspect_tools
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            files={
                'bin/gitleaks':'#!/bin/sh\necho 8.30.1\n',
                'bin/trivy':'#!/bin/sh\necho Version: 0.74.0\n',
                'semgrep-env/bin/python':'#!/bin/sh\necho 1.177.0\n',
                'semgrep-env/bin/semgrep':'#!/bin/sh\necho 1.172.0\n',
                'semgrep-env/lib/python3.14/site-packages/semgrep/bin/semgrep-core':'#!/bin/sh\necho semgrep-core version: 1.177.0\n',
            }
            for relative,body in files.items():
                path=root/relative; path.parent.mkdir(parents=True,exist_ok=True); path.write_text(body); path.chmod(0o700)
            cert=root/'semgrep-env/lib/python3.14/site-packages/certifi/cacert.pem'
            cert.parent.mkdir(parents=True); cert.write_text('certs')
            record=root/'semgrep-env/lib/python3.14/site-packages/semgrep-1.177.0.dist-info/RECORD'
            record.parent.mkdir(parents=True)
            record.write_text('../../../bin/semgrep,sha256=original-wheel-wrapper,999\n')
            self.assertFalse(inspect_tools(root)['semgrep']['ok'])
