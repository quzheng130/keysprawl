"""Acceptance tests AT1-AT22 (the automatable ones)."""
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import KEYSPRAWL, fake

ROOT = KEYSPRAWL.parent


def by_masked(data):
    return {k["masked"]: k for k in data["keys"]}


def snapshot(root):
    out = {}
    for dp, _, fs in os.walk(root):
        for f in fs:
            p = Path(dp) / f
            if p.is_symlink():
                out[str(p)] = ("link", os.readlink(p))
                continue
            st = p.stat()
            out[str(p)] = (hashlib.sha256(p.read_bytes()).hexdigest(), st.st_mode, st.st_mtime_ns, st.st_size)
    return out


def leaks(text, keys):
    """Return any full key, or any 8-char window of a key's random part, found in text."""
    bad = []
    for k in keys:
        rand = re.sub(r"^(sk-proj-|sk-ant-api03-|ghp_|github_pat_)", "", k)
        if k in text:
            bad.append("full")
        bad += [rand[i:i + 8] for i in range(len(rand) - 7) if rand[i:i + 8] in text]
    return bad


def test_at1_empty_home(env):
    r = env.run()
    assert r.returncode == 0, r.stderr
    assert "未发现 key" in r.stdout
    assert re.search(r"不存在 [1-9]\d* 个", r.stdout)
    _, d = env.run_json()
    assert d["keys"] == [] and all(s["reason"] == "not_found" for s in d["skipped"])


def test_at2_same_key_three_copies(env):
    k = fake("openai")
    env.write(".local/share/opencode/auth.json", json.dumps({"openai": {"type": "api", "key": k}}))
    env.write(".codex/auth.json", json.dumps({"OPENAI_API_KEY": k}))
    env.write(".zshrc", "export OPENAI_API_KEY=%s\n" % k)
    r = env.run()
    assert r.returncode == 1
    assert "K1" in r.stdout and "K2" not in r.stdout
    assert "副本数 3" in r.stdout
    for p in ("opencode/auth.json", ".codex/auth.json", ".zshrc"):
        assert p in r.stdout


def test_at3_types_and_locations(at3):
    r, d = at3.run_json()
    assert r.returncode == 1 and len(d["keys"]) == 5
    assert set(d) == {"version", "scanned_at", "keys", "skipped", "notes"}


def test_at3_detail(at3):
    sys.path.insert(0, str(ROOT))
    import keysprawl
    r, d = at3.run_json()
    m = by_masked(d)
    exp = {"opencode": ("OpenAI project key", "opencode/auth.json"),
           "claude": ("Anthropic API key", ".claude/settings.json"),
           "dotenv": ("GitHub token", "proj/.env"), "rc": ("GitHub fine-grained PAT", ".bashrc"),
           "bak": ("OpenAI project key", ".zshrc.bak")}
    for name, (typ, path) in exp.items():
        k = m[keysprawl.mask(at3.k[name])]
        assert k["type"] == typ
        assert any(l["path"].endswith(path) for l in k["locations"]), (name, k)
    claude = m[keysprawl.mask(at3.k["claude"])]
    assert claude["locations"][0]["field"] == "env.ANTHROPIC_API_KEY"


def make_db(path, key):
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE credential (id TEXT, provider_id TEXT, type TEXT, data TEXT)")
    con.execute("INSERT INTO credential VALUES (?,?,?,?)", ("c1", "openai", "api", json.dumps({"key": key})))
    con.commit()
    con.close()


def test_at4_sqlite_readonly(env):
    k = fake("openai")
    db = env.home / ".local/share/opencode/opencode.db"
    db.parent.mkdir(parents=True)
    make_db(db, k)
    before = (hashlib.sha256(db.read_bytes()).hexdigest(), db.stat().st_size, db.stat().st_mtime_ns)
    listing = sorted(os.listdir(db.parent))
    r, d = env.run_json()
    assert r.returncode == 1 and len(d["keys"]) == 1
    assert d["keys"][0]["locations"][0]["kind"] == "sqlite"
    assert (hashlib.sha256(db.read_bytes()).hexdigest(), db.stat().st_size, db.stat().st_mtime_ns) == before
    assert sorted(os.listdir(db.parent)) == listing
    assert not any(n.endswith(("-wal", "-shm", "-journal")) for n in os.listdir(db.parent))


def test_at5_no_key_leak(at3):
    outs = []
    for args in ((), ("--json",), ("--checklist", "out.md")):
        r = at3.run(*args)
        outs += [r.stdout, r.stderr]
    outs.append((at3.cwd / "out.md").read_text(encoding="utf-8"))
    assert leaks("\n".join(outs), at3.keys) == []


def test_at6_mask_format(at3):
    _, d = at3.run_json()
    for k in d["keys"]:
        assert re.fullmatch(r"(sk-proj-|sk-ant-api03-|ghp_|github_pat_)…[A-Za-z0-9]{4}", k["masked"]), k["masked"]
    sys.path.insert(0, str(ROOT))
    import keysprawl
    short = "sk-" + "proj-abc123"
    assert keysprawl.mask(short) == "sk-…(长度 %d)" % len(short) or "abc123"[-4:] not in keysprawl.mask(short)
    assert "c123" not in keysprawl.mask(short)
    assert keysprawl.mask("x" * 30 + "WXYZ") == "…WXYZ(长度 34)"


def test_at7_supplement_no_socket_audit(at3):
    """AT7 itself needs unshare -n + strace (not available here). Supplement: audit hook proves
    no socket is created and no network module is imported during a full scan."""
    code = (
        "import sys\nev=[]\n"
        "sys.addaudithook(lambda e,a: ev.append(e) if e.startswith(('socket.','http','urllib')) else None)\n"
        "sys.argv=['keysprawl','--json']\nsys.path.insert(0,%r)\nimport keysprawl\n"
        "rc=keysprawl.main(['--json'])\n"
        "bad=[m for m in sys.modules if m in ('socket','ssl','http','urllib.request','http.client')]\n"
        "sys.stderr.write('EVENTS=%%s MODS=%%s'%%(ev,bad))\n" % str(ROOT))
    r = subprocess.run([sys.executable, "-B", "-c", code], cwd=at3.cwd, env=at3.env, capture_output=True, text=True)
    assert "EVENTS=[] MODS=[]" in r.stderr, r.stderr


def test_at9_no_network_imports():
    r = subprocess.run(["grep", "-nE", r"\b(socket|http|urllib|requests|ssl|ftplib|smtplib|asyncio)\b",
                        str(KEYSPRAWL)], capture_output=True, text=True)
    # Only allowed hits: documentation URLs inside checklist strings / comments.
    hits = [l for l in r.stdout.splitlines() if not re.search(r"https://", l) and "No network" not in l]
    assert hits == [], hits


def test_at10_nothing_modified(at3):
    snap = snapshot(at3.root)
    at3.run()
    at3.run("--json")
    at3.run("--checklist", "out.md")
    after = snapshot(at3.root)
    new = set(after) - set(snap)
    assert new == {str(at3.cwd / "out.md")}
    for p, v in snap.items():
        assert after[p] == v, p


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs non-root POSIX")
def test_at11_permission_denied(at3):
    p = at3.home / ".bashrc"
    p.chmod(0)
    try:
        r = at3.run()
        assert "权限不足" in r.stderr and ".bashrc" in r.stderr
        assert r.returncode == 1  # other keys still found
        _, d = at3.run_json()
        assert {"path": str(p), "reason": "permission_denied"} in d["skipped"]
        assert len(d["keys"]) == 4
    finally:
        p.chmod(0o644)


@pytest.mark.skipif(os.name != "posix", reason="symlinks: Unix automated, Windows manual")
def test_at12_symlinks(env):
    k = fake("anthropic")
    real = env.write("dotfiles/zshrc", "export ANTHROPIC_API_KEY=%s\n" % k)
    (env.home / ".zshrc").symlink_to(real)
    (env.home / ".bashrc").symlink_to(env.home / "nope")          # dangling
    (env.home / ".profile").symlink_to(env.home / ".zprofile")     # loop
    (env.home / ".zprofile").symlink_to(env.home / ".profile")
    (env.home / ".zshenv").symlink_to(real)                         # second alias path to same file
    r, d = env.run_json()
    assert r.returncode == 1
    key = d["keys"][0]
    assert key["copies"] == 1
    loc = key["locations"][0]
    assert loc["path"].endswith(".zshrc") and any(a.endswith(".zshenv") for a in loc["aliases"])
    reasons = {Path(s["path"]).name: s["reason"] for s in d["skipped"]}
    assert reasons[".bashrc"] == "broken_symlink" and reasons[".profile"] == "broken_symlink"


def test_at13_large_and_binary(env):
    (env.cwd / ".env").write_bytes(b"A=1\n" * (6 * 1024 * 1024 // 4))
    (env.cwd / ".env.bin").write_bytes(b"abc\x00def")
    _, d = env.run_json()
    reasons = {Path(s["path"]).name: s["reason"] for s in d["skipped"]}
    assert reasons[".env"] == "too_large" and reasons[".env.bin"] == "binary"


def test_at14_broken_json(env):
    k = fake("openai")
    env.write(".local/share/opencode/auth.json", '{"openai": {"key": "%s",, BROKEN' % k)
    r, d = env.run_json()
    assert r.returncode == 1 and len(d["keys"]) == 1 and d["keys"][0]["locations"][0]["line"] == 1


def test_at15_env_overrides(env):
    ks = [fake("openai"), fake("anthropic"), fake("github")]
    env.write("alt/codex/auth.json", json.dumps({"OPENAI_API_KEY": ks[0]}))
    env.write("alt/claude/settings.json", json.dumps({"env": {"ANTHROPIC_API_KEY": ks[1]}}))
    env.write("alt/data/opencode/auth.json", json.dumps({"github": {"key": ks[2]}}))
    env.write(".codex/auth.json", json.dumps({"OPENAI_API_KEY": fake("openai")}))  # default location: must be ignored
    _, d = env.run_json(extra_env={"CODEX_HOME": str(env.home / "alt/codex"),
                                   "CLAUDE_CONFIG_DIR": str(env.home / "alt/claude"),
                                   "XDG_DATA_HOME": str(env.home / "alt/data")})
    paths = sorted(l["path"] for k in d["keys"] for l in k["locations"])
    assert len(paths) == 3 and all("/alt/" in p for p in paths), paths


def test_at16_env_var_copy(env):
    k = fake("anthropic")
    env.write(".zshrc", "export ANTHROPIC_API_KEY=%s\n" % k)
    _, d = env.run_json(extra_env={"ANTHROPIC_API_KEY": k})
    assert d["keys"][0]["copies"] == 2 and any(l["kind"] == "env" for l in d["keys"][0]["locations"])
    _, d = env.run_json("--no-env", extra_env={"ANTHROPIC_API_KEY": k})
    assert d["keys"][0]["copies"] == 1


def test_at17_checklist_no_overwrite(at3):
    out = at3.cwd / "out.md"
    out.write_text("keep me", encoding="utf-8")
    r = at3.run("--checklist", "out.md")
    assert r.returncode == 2 and out.read_text(encoding="utf-8") == "keep me"
    r = at3.run("--checklist", "out.md", "--force")
    assert r.returncode == 1 and "keep me" not in out.read_text(encoding="utf-8")


def test_at18_checklist_groups(env):
    env.write(".zshrc", "export OPENAI_API_KEY=%s\nexport GH_TOKEN=%s\n" % (fake("openai"), fake("github")))
    env.run("--checklist", "out.md")
    md = (env.cwd / "out.md").read_text(encoding="utf-8")
    assert "## OpenAI" in md and "https://platform.openai.com/api-keys" in md
    assert "## GitHub" in md and "https://github.com/settings/tokens" in md
    assert "https://docs.github.com/en/rest/credentials/revoke" in md
    assert "## Anthropic" not in md and "platform.claude.com" not in md and "console.anthropic.com" not in md
    assert ".zshrc:1" in md and "吊销" in md


def test_at19_unknown_arg(env):
    r = env.run("--foo")
    assert r.returncode == 2 and "usage" in r.stderr.lower()


def test_at20_internal_error(at3):
    r = at3.run(extra_env={"KEYSPRAWL_TEST_CRASH": "boom"})
    assert r.returncode == 3
    assert "内部错误" in r.stderr and "Traceback" not in r.stderr and "boom" not in r.stderr
    assert leaks(r.stdout + r.stderr, at3.keys) == []


def test_at22_core_lines():
    n = sum(1 for l in KEYSPRAWL.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.strip().startswith("#"))
    print("core lines:", n)
    assert n <= 300, n


def test_misc_version_help_missing_path(env):
    assert env.run("--version").returncode == 0
    assert env.run("--help").returncode == 0
    r = env.run("scan", "--path", str(env.root / "missing"))
    assert r.returncode == 0 and "目录不存在" in r.stderr
