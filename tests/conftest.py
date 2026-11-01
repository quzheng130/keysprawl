"""Test fixtures. Fake keys are generated at run time and only ever written to tmp dirs."""
import json
import os
import random
import string
import subprocess
import sys
from pathlib import Path

import pytest

KEYSPRAWL = Path(__file__).resolve().parent.parent / "keysprawl.py"
ALNUM = string.ascii_letters + string.digits
SCRUB = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CODEX_API_KEY",
         "GITHUB_TOKEN", "GH_TOKEN", "XDG_DATA_HOME", "CODEX_HOME", "CLAUDE_CONFIG_DIR",
         "OPENCODE_DB", "KEYSPRAWL_TEST_CRASH"]


def rnd(n):
    return "".join(random.SystemRandom().choice(ALNUM) for _ in range(n))


def fake(kind):
    return {"openai": lambda: "sk-" + "proj-" + rnd(48),
            "anthropic": lambda: "sk-" + "ant-api03-" + rnd(40),
            "github": lambda: "gh" + "p_" + rnd(36),
            "github_pat": lambda: "github" + "_pat_" + rnd(40)}[kind]()


class Env:
    def __init__(self, tmp):
        self.root = tmp
        self.home = tmp / "home"
        self.cwd = tmp / "proj"
        self.home.mkdir()
        self.cwd.mkdir()
        self.env = {k: v for k, v in os.environ.items() if k not in SCRUB}
        self.env.update(HOME=str(self.home), USERPROFILE=str(self.home), PYTHONDONTWRITEBYTECODE="1")
        self.keys = []

    def write(self, rel, text, base=None):
        p = (base or self.home) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p

    def run(self, *args, extra_env=None):
        env = dict(self.env, **(extra_env or {}))
        r = subprocess.run([sys.executable, "-B", str(KEYSPRAWL), *args], cwd=self.cwd, env=env,
                           capture_output=True, text=True, timeout=60)
        return r

    def run_json(self, *args, **kw):
        r = self.run("--json", *args, **kw)
        return r, json.loads(r.stdout)


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


@pytest.fixture
def at3(env):
    """AT3 environment: different key types across OpenCode, Claude env, .env, shell rc, *.bak."""
    k = {"opencode": fake("openai"), "claude": fake("anthropic"), "dotenv": fake("github"),
         "rc": fake("github_pat"), "bak": fake("openai")}
    env.write(".local/share/opencode/auth.json", json.dumps({"openai": {"type": "api", "key": k["opencode"]}}))
    env.write(".claude/settings.json", json.dumps({"env": {"ANTHROPIC_API_KEY": k["claude"]}}))
    env.write(".env", "GITHUB_TOKEN=%s\n" % k["dotenv"], base=env.cwd)
    env.write(".bashrc", "alias ll='ls -l'\nexport GH_TOKEN=%s\n" % k["rc"])
    env.write(".zshrc.bak", "export OPENAI_API_KEY=%s\n" % k["bak"])
    env.keys = list(k.values())
    env.k = k
    return env
