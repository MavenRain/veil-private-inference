"""Exercise the native NVML boundary with an ABI-compatible test library."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class GpuModeTests(unittest.TestCase):
    def test_native_guard_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake = root / "fake.c"
            fake.write_text('''#include <stdlib.h>
typedef struct { unsigned int environment, ccFeature, devToolsMode; } State;
static unsigned int value(const char *key, unsigned int fallback) {
    const char *v = getenv(key); return v ? (unsigned int)strtoul(v, 0, 10) : fallback;
}
int nvmlInit_v2(void) { return (int)value("FAKE_ERROR", 0); }
int nvmlShutdown(void) { return 0; }
int nvmlSystemGetConfComputeState(State *s) {
    s->environment=value("FAKE_ENV",2); s->ccFeature=value("FAKE_CC",1);
    s->devToolsMode=value("FAKE_DEBUG",0); return 0;
}
int nvmlDeviceGetCount_v2(unsigned int *n) { *n=value("FAKE_COUNT",1); return 0; }
int nvmlSystemGetConfComputeGpusReadyState(unsigned int *n) { *n=value("FAKE_READY",1); return 0; }
''')
            options = ["-dynamiclib"] if sys.platform == "darwin" else ["-shared", "-fPIC"]
            subprocess.run(["cc", *options, str(fake), "-o", str(root / "libnvidia-ml.so.1")], check=True)
            source = Path(__file__).with_name("gpu-cc-check.c")
            subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", str(source), "-ldl", "-o", str(root / "guard")], check=True)
            env = {**os.environ, "LD_LIBRARY_PATH": str(root), "DYLD_LIBRARY_PATH": str(root)}
            good = subprocess.run([str(root / "guard")], capture_output=True, env=env, check=True)
            self.assertEqual(json.loads(good.stdout), {"cc": True, "debug": False, "production": True, "ready": True, "gpus": 1})
            for key, value in (("FAKE_CC", "0"), ("FAKE_DEBUG", "1"), ("FAKE_ENV", "1"),
                               ("FAKE_COUNT", "2"), ("FAKE_READY", "0"), ("FAKE_ERROR", "1")):
                bad = subprocess.run([str(root / "guard")], capture_output=True, env={**env, key: value})
                self.assertNotEqual(bad.returncode, 0, key)
                self.assertEqual(bad.stdout, b"")


if __name__ == "__main__":
    unittest.main()
