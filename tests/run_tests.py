"""Zero-dependency test runner: discovers test_* functions, prints a summary."""
import os, sys, traceback, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
passed = failed = 0
failures = []
for fname in sorted(os.listdir(HERE)):
    if not (fname.startswith("test_") and fname.endswith(".py")):
        continue
    spec = importlib.util.spec_from_file_location(fname[:-3], os.path.join(HERE, fname))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for name in sorted(dir(mod)):
        if not name.startswith("test_"):
            continue
        fn = getattr(mod, name)
        if not callable(fn):
            continue
        try:
            fn(); passed += 1; print(f"  ok    {fname[:-3]}.{name}")
        except Exception:
            failed += 1; failures.append((fname, name, traceback.format_exc()))
            print(f"  FAIL  {fname[:-3]}.{name}")
print()
for f, n, tb in failures:
    print(f"=== {f}::{n} ===\n{tb}")
print(f"{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
