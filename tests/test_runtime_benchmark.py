from __future__ import annotations
import importlib.util, unittest
from pathlib import Path
SCRIPT=Path(__file__).resolve().parents[1]/"scripts"/"benchmark_v05_runtime.py"; SPEC=importlib.util.spec_from_file_location("benchmark_v05_runtime",SCRIPT)
if SPEC is None or SPEC.loader is None: raise RuntimeError("cannot load runtime benchmark")
benchmark_module=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(benchmark_module)
class RuntimeBenchmarkTests(unittest.TestCase):
    def test_percentile_is_bounded_and_deterministic(self)->None:
        values=[9.0,1.0,5.0,3.0,7.0]; self.assertEqual(benchmark_module.percentile(values,0.0),1.0); self.assertEqual(benchmark_module.percentile(values,.5),5.0); self.assertEqual(benchmark_module.percentile(values,1.0),9.0); self.assertEqual(benchmark_module.percentile([], .95),0.0)
    def test_cycle_bounds_are_rejected_before_host_collection(self)->None:
        with self.assertRaisesRegex(ValueError,"between 2 and 50"): benchmark_module.benchmark(Path("missing.json"),cycles=1)
        with self.assertRaisesRegex(ValueError,"between 2 and 50"): benchmark_module.benchmark(Path("missing.json"),cycles=51)
if __name__=="__main__":unittest.main()
