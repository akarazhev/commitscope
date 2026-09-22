from pathlib import Path
import subprocess
import tempfile
import unittest

class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.repo=self.root/'repo'; self.repo.mkdir()
        self.git('init','-q'); self.git('config','user.email','demo@example.invalid'); self.git('config','user.name','Demo')
        (self.repo/'app.py').write_text('print("hello")\n'); self.git('add','.'); self.git('commit','-qm','initial')
    def git(self,*args):
        return subprocess.check_output(['git','-C',str(self.repo),*args],stderr=subprocess.STDOUT).decode().strip()
    def test_snapshot_has_commit_content(self):
        from sec_review.snapshot import export_snapshot
        meta=export_snapshot(self.repo,self.root/'snapshot')
        self.assertEqual(meta['head'],self.git('rev-parse','HEAD'))
        self.assertEqual((self.root/'snapshot/app.py').read_text(),'print("hello")\n')
        self.assertEqual(meta['file_count'],1)
    def test_commit_replacement_cannot_change_exact_snapshot(self):
        from sec_review.snapshot import export_snapshot, resolve_exact_commit
        original = self.git('rev-parse', 'HEAD')
        (self.repo/'app.py').write_text('replacement commit\n')
        self.git('commit', '-qam', 'replacement')
        replacement = self.git('rev-parse', 'HEAD')
        self.git('replace', original, replacement)
        self.assertEqual(resolve_exact_commit(self.repo, original), original)
        meta = export_snapshot(self.repo, self.root/'snapshot', ref=original)
        self.assertEqual(meta['head'], original)
        self.assertEqual((self.root/'snapshot/app.py').read_text(), 'print("hello")\n')

    def test_blob_replacement_cannot_change_exact_snapshot(self):
        from sec_review.snapshot import export_snapshot
        original = self.git('rev-parse', 'HEAD')
        blob = self.git('rev-parse', 'HEAD:app.py')
        replacement = subprocess.check_output(
            ['git', '-C', str(self.repo), 'hash-object', '-w', '--stdin'],
            input=b'replacement blob\n').decode().strip()
        self.git('replace', blob, replacement)
        meta = export_snapshot(self.repo, self.root/'snapshot', ref=original)
        self.assertEqual(meta['head'], original)
        self.assertEqual((self.root/'snapshot/app.py').read_text(), 'print("hello")\n')
    def test_dirty_tree_rejected(self):
        from sec_review.snapshot import export_snapshot
        from sec_review.core import ReviewError
        (self.repo/'app.py').write_text('changed')
        with self.assertRaises(ReviewError): export_snapshot(self.repo,self.root/'snapshot')
    def test_untracked_files_rejected(self):
        from sec_review.snapshot import export_snapshot
        from sec_review.core import ReviewError
        (self.repo/'extra.py').write_text('x=1')
        with self.assertRaises(ReviewError): export_snapshot(self.repo,self.root/'snapshot')
    def test_symlink_commit_rejected(self):
        from sec_review.snapshot import export_snapshot
        from sec_review.core import ReviewError
        (self.repo/'link').symlink_to('/etc/passwd'); self.git('add','.'); self.git('commit','-qm','link')
        with self.assertRaises(ReviewError): export_snapshot(self.repo,self.root/'snapshot')
    def test_export_ignore_does_not_hide_source(self):
        from sec_review.snapshot import export_snapshot
        (self.repo/'.gitattributes').write_text('app.py export-ignore\n'); self.git('add','.'); self.git('commit','-qm','attrs')
        export_snapshot(self.repo,self.root/'snapshot')
        self.assertTrue((self.root/'snapshot/app.py').exists())
    def test_scanner_ignore_file_not_trusted(self):
        from sec_review.snapshot import export_snapshot
        (self.repo/'.semgrepignore').write_text('*\n'); self.git('add','.'); self.git('commit','-qm','ignore')
        m=export_snapshot(self.repo,self.root/'snapshot')
        self.assertEqual((self.root/'snapshot/.semgrepignore').read_text(),'')
        self.assertIn('.semgrepignore',m['neutralized_controls'])
    def test_snapshot_size_limit_rejected(self):
        from sec_review.snapshot import export_snapshot
        from sec_review.core import ReviewError
        with self.assertRaises(ReviewError): export_snapshot(self.repo,self.root/'snapshot',max_bytes=1)
    def test_bad_revision_rejected(self):
        from sec_review.snapshot import export_snapshot
        from sec_review.core import ReviewError
        with self.assertRaises(ReviewError): export_snapshot(self.repo,self.root/'snapshot',ref='--help')
    def test_pinned_snapshot_can_be_reexported_with_dirty_worktree(self):
        from sec_review.snapshot import export_snapshot
        head=self.git('rev-parse','HEAD'); (self.repo/'app.py').write_text('uncommitted')
        m=export_snapshot(self.repo,self.root/'snapshot',ref=head,require_clean=False)
        self.assertEqual((self.root/'snapshot/app.py').read_text(),'print("hello")\n')
    def test_git_fsmonitor_hook_is_disabled(self):
        from sec_review.snapshot import export_snapshot
        evil=self.root/'evil.sh'; evil.write_text('#!/bin/sh\ntouch "'+str(self.root/'executed')+'"\n'); evil.chmod(0o700)
        self.git('config','core.fsmonitor',str(evil))
        export_snapshot(self.repo,self.root/'snapshot')
        self.assertFalse((self.root/'executed').exists())
