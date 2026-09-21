"""Real application behavior tests. No scanner doubles and no network."""
import importlib.util
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
def load(which):
    spec=importlib.util.spec_from_file_location('demo_'+which,ROOT/'examples'/which/'app.py')
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

class DemoApplicationTests(unittest.TestCase):
    def test_vulnerable_fixture_demonstrates_cross_tenant_read(self):
        self.assertEqual(load('vulnerable').read_invoice('tenant-a','2')['tenant'],'tenant-b')
    def test_fixed_fixture_blocks_cross_tenant_read(self):
        with self.assertRaises(PermissionError): load('fixed').read_invoice('tenant-a','2')
    def test_fixed_fixture_preserves_authorized_access(self):
        self.assertEqual(load('fixed').read_invoice('tenant-a','1')['amount'],100)
    def test_fixed_fixture_does_not_distinguish_missing_from_unauthorized(self):
        m=load('fixed'); messages=[]
        for id in ('2','999'):
            try: m.read_invoice('tenant-a',id)
            except PermissionError as e: messages.append(str(e))
        self.assertEqual(messages[0],messages[1])
    def test_calculator_keeps_allowed_arithmetic(self):
        for v in ('vulnerable','fixed'):
            self.assertEqual(load(v).calculate_total('2+3*4'),14)
    def test_fixed_calculator_rejects_function_calls(self):
        with self.assertRaises(ValueError): load('fixed').calculate_total('sum([1, 2])')
    def test_fixed_calculator_rejects_large_inputs(self):
        with self.assertRaises(ValueError): load('fixed').calculate_total('1+'*100+'1')
    def test_fixed_diagnostics_reject_arbitrary_commands(self):
        with self.assertRaises(ValueError): load('fixed').run_diagnostic('arbitrary-command')
