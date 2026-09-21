"""Regression tests for first installation; external services are not exercised."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from sec_review.auth import prepare_claude
from sec_review.core import ProcessResult, ReviewError, ROOT

class FreshStartTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve()
        self.home=self.root/'user'; self.home.mkdir()
        self.work=self.root/'work'; self.work.mkdir()
    def protocol(self, argv, cwd, env, timeout, stdin=None):
        if '--help' in argv:return ProcessResult(0,'Usage: claude','',0)
        if '--version' in argv:return ProcessResult(0,'2.1.999 (Claude Code)','',0)
        return ProcessResult(0,json.dumps({'loggedIn':True,'authMethod':'claude.ai','apiProvider':'firstParty'}),'',0)
    def test_native_claude_discovered_without_shell_restart(self):
        binary=self.home/'.local/bin/claude'; binary.parent.mkdir(parents=True)
        binary.write_text('#!/bin/sh\nexit 91\n'); binary.chmod(0o700)
        with patch.dict(os.environ,{'HOME':str(self.home),'PATH':'/usr/bin:/bin'},clear=True), patch('sec_review.auth.execute',side_effect=self.protocol):
            prepared=prepare_claude(self.work,'subscription')
        self.assertEqual(prepared.executable,str(binary))
    def test_native_launcher_may_be_an_official_style_symlink(self):
        binary=self.home/'.local/share/claude/versions/2.1.999';binary.parent.mkdir(parents=True)
        binary.write_text('#!/bin/sh\nexit 91\n');binary.chmod(0o700)
        launcher=self.home/'.local/bin/claude';launcher.parent.mkdir(parents=True);launcher.symlink_to(binary)
        with patch.dict(os.environ,{'HOME':str(self.home),'PATH':'/usr/bin:/bin'},clear=True), patch('sec_review.auth.execute',side_effect=self.protocol):
            prepared=prepare_claude(self.work,'subscription')
        self.assertEqual(Path(prepared.executable).resolve(),binary)
    def test_internal_temp_alias_is_canonicalized_without_relaxing_target_policy(self):
        alias=self.root/'temp-alias';alias.symlink_to(self.work,target_is_directory=True)
        seen=[]
        def capture(argv,cwd,env,timeout,stdin=None):
            seen.append((cwd,env));return self.protocol(argv,cwd,env,timeout,stdin)
        with patch.dict(os.environ,{'HOME':str(self.home),'PATH':'/usr/bin:/bin'},clear=True), patch('sec_review.auth.shutil.which',return_value='/bin/claude'), patch('sec_review.auth.execute',side_effect=capture):
            prepare_claude(alias,'subscription')
        self.assertTrue(seen)
        for cwd,env in seen:self.assertEqual(cwd,cwd.resolve())
    def test_shell_wrapper_honors_explicit_python(self):
        selected=self.root/'chosen-python'; selected.write_text('#!/bin/sh\nprintf "SELECTED_INTERPRETER\\n"\n');selected.chmod(0o700)
        other=self.root/'python3';other.write_text('#!/bin/sh\nexit 43\n');other.chmod(0o700)
        env={'HOME':str(self.home),'PATH':str(self.root)+':/usr/bin:/bin','PYTHON':str(selected)}
        r=subprocess.run(['/bin/sh',str(ROOT/'scripts/bootstrap.sh')],env=env,capture_output=True,text=True)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('SELECTED_INTERPRETER',r.stdout)
    def test_preflight_command_is_available_before_installation(self):
        from sec_review.cli import parser
        import contextlib,io
        try:
            with contextlib.redirect_stderr(io.StringIO()):args=parser().parse_args(['preflight'])
        except SystemExit:self.fail('A first-install prerequisite check must be available before downloading tools')
        self.assertEqual(args.command,'preflight')

if __name__=='__main__':unittest.main()
