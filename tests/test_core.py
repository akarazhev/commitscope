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

class InstallerTests(unittest.TestCase):
    def archive(self, path, name, kind=tarfile.REGTYPE, data=b'binary'):
        with tarfile.open(path, 'w:gz') as t:
            info=tarfile.TarInfo(name); info.type=kind; info.size=len(data) if kind==tarfile.REGTYPE else 0
            t.addfile(info, io.BytesIO(data) if kind==tarfile.REGTYPE else None)
    def test_verified_binary_extraction(self):
        from sec_review.tools import extract_binary
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); self.archive(p/'a.tgz','gitleaks'); extract_binary(p/'a.tgz','gitleaks',p/'binary')
            self.assertEqual((p/'binary').read_bytes(),b'binary')
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
