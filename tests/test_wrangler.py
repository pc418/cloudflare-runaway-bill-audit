import json
import tempfile
import unittest
from pathlib import Path

import _util  # noqa: F401
from nobill.providers.cloudflare import wrangler


class JsoncTest(unittest.TestCase):
    def test_comments_and_trailing_commas(self):
        text = ('{\n  // a comment with "quotes"\n  "name": "w", /* block\n comment */\n'
                '  "url": "https://example.com/x", // keep the // inside strings\n'
                '  "list": [1, 2,],\n}\n')
        data = json.loads(wrangler.strip_jsonc(text))
        self.assertEqual(data, {"name": "w", "url": "https://example.com/x", "list": [1, 2]})

    def test_commas_inside_strings_are_preserved(self):
        text = ('{\n  "main": "../api,]/src/index.ts",\n  "vars": {"A": "x,}", "B": "a\\",]b", "C": ",\\n]"},\n'
                '  "list": ["p,]", "q" , // trailing\n  ],\n}\n')
        data = json.loads(wrangler.strip_jsonc(text))
        self.assertEqual(data, {"main": "../api,]/src/index.ts", "vars": {"A": "x,}", "B": 'a",]b', "C": ",\n]"},
                                "list": ["p,]", "q"]})


class ViewsTest(unittest.TestCase):
    def write(self, name: str, text: str) -> wrangler.ConfigFile:
        d = Path(tempfile.mkdtemp())
        (d / name).write_text(text)
        return wrangler.parse(d / name, d)

    def test_env_overrides(self):
        cfg = self.write("wrangler.toml", (
            'name = "api"\nmain = "src/index.ts"\nworkers_dev = false\n[limits]\ncpu_ms = 50\n'
            '[ai]\nbinding = "AI"\n[[r2_buckets]]\nbinding = "MEDIA"\nbucket_name = "media"\n'
            '[env.staging]\nworkers_dev = true\n[[env.staging.r2_buckets]]\nbinding = "MEDIA"\nbucket_name = "media-staging"\n'
            '[env.prod]\nname = "api-production"\n'))
        self.assertIsNone(cfg.error)
        views = {v.env: v for v in wrangler.views(cfg)}
        self.assertEqual(set(views), {None, "staging", "prod"})
        st = views["staging"]
        self.assertEqual(st.name, "api-staging")
        self.assertIs(st.get("workers_dev"), True)            # overridden
        self.assertEqual(st.get("limits"), {"cpu_ms": 50})   # inheritable
        self.assertIsNone(st.ai_binding())                   # bindings are not inherited
        self.assertEqual(st.r2_bindings(), {"MEDIA": "media-staging"})
        self.assertEqual(views["prod"].name, "api-production")
        self.assertEqual(views["prod"].r2_bindings(), {})
        self.assertGreater(st.env_line, 1)

    def test_parse_errors_are_reported(self):
        bad_toml = self.write("wrangler.toml", 'name = "x\n')
        self.assertIsNone(bad_toml.raw)
        self.assertIn("TOML parse error", bad_toml.error)
        bad_json = self.write("wrangler.jsonc", '{ "name": "x" "main": "y" }')
        self.assertIsNone(bad_json.raw)
        self.assertIn("JSON parse error", bad_json.error)

    def test_discovery_skips_dependencies_and_dot_dirs(self):
        d = Path(tempfile.mkdtemp())
        for rel in ("wrangler.toml", "workers/api/wrangler.jsonc", "workers/api/wrangler.test.jsonc",
                    "node_modules/pkg/wrangler.toml", ".claude/skills/wrangler/wrangler.toml", "dist/w/wrangler.json"):
            p = d / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("{}" if rel.endswith("json") or rel.endswith("jsonc") else 'name = "x"\n')
        found = sorted(str(p.relative_to(d)) for p in wrangler.discover(d))
        self.assertEqual(found, ["workers/api/wrangler.jsonc", "workers/api/wrangler.test.jsonc", "wrangler.toml"])


if __name__ == "__main__":
    unittest.main()
