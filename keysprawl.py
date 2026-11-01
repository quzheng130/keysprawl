#!/usr/bin/env python3
# keysprawl v0.1 - read-only, offline scan for AI/GitHub keys in local agent configs.
# SPDX-License-Identifier: MIT  (c) 2026 quzheng
# Runtime: Python 3.9+ standard library only. No network modules are imported.
import argparse
import datetime
import json
import os
import re
import sqlite3
import stat
import sys
from pathlib import Path

VERSION = "0.1.0"
MAX_TEXT = 5 * 1024 * 1024
ENV_NAMES = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
             "CODEX_API_KEY", "GITHUB_TOKEN", "GH_TOKEN"]
B = r"(?<![A-Za-z0-9_\-])"
E = r"(?![A-Za-z0-9_\-])"
# (type label, provider, visible prefix regex, full regex). Order matters: first match wins.
RULES = [
    ("Anthropic API key", "Anthropic", "sk-ant-api03-", r"sk-ant-api03-[A-Za-z0-9_\-]{20,}"),
    ("Anthropic Admin key", "Anthropic", "sk-ant-admin01-", r"sk-ant-admin01-[A-Za-z0-9_\-]{20,}"),
    ("其他 Anthropic 令牌", "Anthropic", None, r"sk-ant-[a-z0-9]+-[A-Za-z0-9_\-]{16,}"),
    ("OpenAI project key", "OpenAI", "sk-proj-", r"sk-proj-[A-Za-z0-9_\-]{20,}"),
    ("OpenAI service account key", "OpenAI", "sk-svcacct-", r"sk-svcacct-[A-Za-z0-9_\-]{20,}"),
    ("OpenAI admin key", "OpenAI", "sk-admin-", r"sk-admin-[A-Za-z0-9_\-]{20,}"),
    ("OpenAI legacy key", "OpenAI", "sk-", r"sk-[A-Za-z0-9]{10,}T3BlbkFJ[A-Za-z0-9]{10,}"),
    ("GitHub fine-grained PAT", "GitHub", "github_pat_", r"github_pat_[A-Za-z0-9_]{22,}"),
    ("GitHub token", "GitHub", None, r"gh[pousr]_[A-Za-z0-9]{30,}"),
]
KEY_RE = re.compile(B + "(" + "|".join("(?:%s)" % r[3] for r in RULES) + ")" + E)
RULE_RES = [re.compile(r[3] + "$") for r in RULES]
ASSIGN_RE = re.compile(r"(?:export\s+|set\s+-gx\s+|\$env:)?\b(%s)\b[\"']?\s*[=:\s]\s*[\"']?([^\"'\s,;}]+)"
                       % "|".join(ENV_NAMES))
DASH = {"OpenAI": "https://platform.openai.com/api-keys",
        "Anthropic": "https://platform.claude.com/settings/keys",
        "GitHub": "https://github.com/settings/tokens"}
CURRENT = {"path": None}


def classify(value):
    for rule, rx in zip(RULES, RULE_RES):
        if rx.match(value):
            prefix = rule[2] or re.match(r"(sk-ant-[a-z0-9]+-|gh[pousr]_)", value).group(1)
            return rule[0], rule[1], prefix
    return "未识别格式", "Other", ""


def mask(value):
    typ, _, prefix = classify(value)
    if len(value) < 20:
        return "%s…(长度 %d)" % (prefix, len(value))
    if not prefix:
        return "…%s(长度 %d)" % (value[-4:], len(value))
    return "%s…%s" % (prefix, value[-4:])


class Scan:
    def __init__(self):
        self.keys = {}          # full value -> {"locs": [...], "units": set()}
        self.seen = {}          # (dev, ino) -> list of location dicts (for alias recording)
        self.skipped, self.notes = [], []
        self.scanned, self.done = 0, set()

    def add(self, value, unit, loc):
        k = self.keys.setdefault(value, {"locs": [], "units": set()})
        k["units"].add(unit)
        k["locs"].append(loc)
        if unit[0] != "env":
            self.seen.setdefault(unit, []).append(loc)

    def skip(self, path, reason, warn=None):
        self.skipped.append({"path": str(path), "reason": reason})
        if warn:
            print(warn, file=sys.stderr)

    def find_in_text(self, text, unit, path, kind, field=None, line=None):
        found = {m.group(1) for m in KEY_RE.finditer(text)}
        for m in ASSIGN_RE.finditer(text):
            v = m.group(2)
            if len(v) >= 8 and not v.startswith("$") and not KEY_RE.search(v):
                found.add(v)
        for v in found:
            loc = {"path": str(path), "kind": kind, "line": line, "field": field}
            self.add(v, unit, {a: b for a, b in loc.items() if b is not None})

    def walk_json(self, obj, unit, path, kind, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                f = "%s.%s" % (prefix, k) if prefix else str(k)
                if isinstance(v, str) and k in ENV_NAMES:
                    self.find_in_text('%s="%s"' % (k, v), unit, path, kind, field=f)
                else:
                    self.walk_json(v, unit, path, kind, f)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                self.walk_json(v, unit, path, kind, "%s[%d]" % (prefix, i))
        elif isinstance(obj, str):
            self.find_in_text(obj, unit, path, kind, field=prefix)

    def scan_file(self, path, kind="file"):
        path = Path(path)
        CURRENT["path"] = str(path)
        if os.environ.get("KEYSPRAWL_TEST_CRASH"):
            raise RuntimeError("test hook: " + os.environ["KEYSPRAWL_TEST_CRASH"])
        try:
            os.lstat(path)
        except FileNotFoundError:
            return self.skip(path, "not_found")
        except PermissionError:
            return self.skip(path, "permission_denied", "无法读取（权限不足）：%s" % path)
        try:
            st = os.stat(path)
        except PermissionError:
            return self.skip(path, "permission_denied", "无法读取（权限不足）：%s" % path)
        except OSError:
            return self.skip(path, "broken_symlink")
        if not stat.S_ISREG(st.st_mode):
            return self.skip(path, "not_a_file")
        unit = (st.st_dev, st.st_ino)
        if unit in self.done:
            return [loc.setdefault("aliases", []).append(str(path)) for loc in self.seen.get(unit, [])]
        self.done.add(unit)
        try:
            with open(path, "rb") as fh:
                head = fh.read(16)
                if head.startswith(b"SQLite format 3\x00"):
                    self.scanned += 1
                    return self.scan_sqlite(path, unit)
                if st.st_size > MAX_TEXT:
                    return self.skip(path, "too_large")
                data = head + fh.read()
        except PermissionError:
            return self.skip(path, "permission_denied", "无法读取（权限不足）：%s" % path)
        except OSError:
            return self.skip(path, "unreadable", "无法读取：%s" % path)
        if b"\x00" in data:
            return self.skip(path, "binary")
        self.scanned += 1
        text = data.decode("utf-8", errors="replace")
        if path.name.startswith(".env.") and "example" in path.name:
            kind = "example"
        if path.suffix == ".json":
            try:
                return self.walk_json(json.loads(text), unit, path, kind)
            except ValueError:
                pass
        for n, line in enumerate(text.splitlines(), 1):
            self.find_in_text(line, unit, path, kind, line=n)

    def scan_sqlite(self, path, unit):
        uri = "file:%s?mode=ro&immutable=1" % path.resolve().as_posix().replace("?", "%3f")
        try:
            con = sqlite3.connect(uri, uri=True)
            try:
                tables = [r[0] for r in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")]
                creds = [t for t in tables if "credential" in t.lower() or t.lower() == "auth"]
                if not creds:
                    return self.skip(path, "db_unknown_schema")
                for t in creds:
                    q = 'SELECT * FROM "%s"' % t.replace('"', '""')
                    cur = con.execute(q)
                    cols = [d[0] for d in cur.description]
                    for row in cur:
                        for c, v in zip(cols, row):
                            if isinstance(v, bytes):
                                v = v.decode("utf-8", errors="replace")
                            if isinstance(v, str):
                                self.find_in_text(v, unit, path, "sqlite", field="%s.%s" % (t, c))
            finally:
                con.close()
        except sqlite3.DatabaseError as e:
            locked = "locked" in str(e).lower() or "busy" in str(e).lower()
            self.skip(path, "db_locked" if locked else "db_unknown_schema")

    def scan_env(self):
        for name in ENV_NAMES:
            v = os.environ.get(name)
            if v:
                self.find_in_text('%s="%s"' % (name, v), ("env", name), "$" + name, "env")


def default_targets(home, cwd):
    env = os.environ
    data = Path(env.get("XDG_DATA_HOME") or home / ".local" / "share") / "opencode"
    claude = Path(env.get("CLAUDE_CONFIG_DIR") or home / ".claude")
    codex = Path(env.get("CODEX_HOME") or home / ".codex")
    docs = home / "Documents"
    t = [data / "auth.json", Path(env.get("OPENCODE_DB") or data / "opencode.db"),
         home / ".config" / "opencode" / "opencode.json", cwd / "opencode.json",
         claude / "settings.json", claude / ".credentials.json", home / ".claude.json",
         cwd / ".claude" / "settings.json", cwd / ".claude" / "settings.local.json",
         codex / "auth.json", codex / "config.toml"]
    t += [home / n for n in (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".zshenv")]
    t += [home / ".config" / "fish" / "config.fish"]
    t += [docs / d / "Microsoft.PowerShell_profile.ps1" for d in ("PowerShell", "WindowsPowerShell")]
    backups = []
    for p in t:
        backups += [p.with_name(p.name + s) for s in (".bak", ".old", "~", ".orig")]
    return t + backups


def env_files(root, depth=4):
    out = []
    for dirpath, dirs, files in os.walk(root):
        rel = Path(dirpath).relative_to(root)
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "vendor")]
        if len(rel.parts) >= depth - 1:
            dirs[:] = []
        out += [Path(dirpath) / f for f in sorted(files) if f == ".env" or f.startswith(".env.")]
    return out


def checklist(result):
    lines = ["# keysprawl 止损清单", "",
             "> 本清单只含掩码，不含完整 key。生成时间：%s" % result["scanned_at"], ""]
    for prov in ("OpenAI", "Anthropic", "GitHub", "Other"):
        ks = [k for k in result["keys"] if k["provider"] == prov]
        if not ks:
            continue
        lines += ["## %s" % (prov if prov != "Other" else "未识别格式（按变量名发现）"), ""]
        if prov in DASH:
            lines += ["1. 打开后台：%s ，找到下面这些 key 并吊销。" % DASH[prov]]
        else:
            lines += ["1. 按变量名判断它属于哪家服务，到对应后台吊销。"]
        lines += ["2. 新建 key：每个工具单独一个 key，设过期时间和花费上限"
                  "（参考 https://help.openai.com/en/articles/5112595-best-practices-for-api-key-safety ）。",
                  "3. 把下面每个本机位置改成新 key（或删掉不需要的副本）。",
                  "4. 回到后台查看近期用量，确认没有异常调用。"]
        if prov == "GitHub":
            lines += ["5. GitHub 还提供官方吊销接口，文档：https://docs.github.com/en/rest/credentials/revoke"
                      " （keysprawl 不会调用它）。"]
        lines.append("")
        for k in ks:
            lines.append("- [ ] %s `%s`（%s，%d 份副本）" % (k["id"], k["masked"], k["type"], k["copies"]))
            for loc in k["locations"]:
                lines.append("  - [ ] %s" % fmt_loc(loc))
        lines.append("")
    return "\n".join(lines)


def fmt_loc(loc):
    s = loc["path"]
    if "line" in loc:
        s += ":%d" % loc["line"]
    if "field" in loc:
        s += " [%s]" % loc["field"]
    if loc["kind"] == "example":
        s += "（示例文件）"
    if loc.get("aliases"):
        s += "（别名：%s）" % ", ".join(loc["aliases"])
    return s


def run(args):
    home, cwd = Path.home(), Path.cwd()
    sc = Scan()
    targets = default_targets(home, cwd) + env_files(cwd)
    for p in args.path or []:
        if not Path(p).is_dir():
            print("警告：目录不存在，已跳过：%s" % p, file=sys.stderr)
            sc.skipped.append({"path": p, "reason": "not_found"})
            continue
        targets += env_files(Path(p))
    for t in targets:
        sc.scan_file(t)
    if not args.no_env:
        sc.scan_env()
    CURRENT["path"] = None
    keys = []
    for i, (v, k) in enumerate(sorted(sc.keys.items(), key=lambda kv: kv[1]["locs"][0]["path"]), 1):
        typ, prov, _ = classify(v)
        keys.append({"id": "K%d" % i, "type": typ, "provider": prov, "masked": mask(v),
                     "copies": len(k["units"]), "locations": k["locs"]})
    sc.notes.append("Claude Code（macOS）和 Codex（keyring 模式）的凭据可能在系统钥匙串里，本工具不读。")
    return {"version": VERSION,
            "scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "keys": keys, "skipped": sc.skipped, "notes": sc.notes, "_scanned": sc.scanned}


def print_table(r):
    if not r["keys"]:
        print("未发现 key。")
    for k in r["keys"]:
        print("%-4s %-28s %-24s 副本数 %d" % (k["id"], k["type"], k["masked"], k["copies"]))
        for loc in k["locations"]:
            print("       - " + fmt_loc(loc))
    cnt = {}
    for s in r["skipped"]:
        cnt[s["reason"]] = cnt.get(s["reason"], 0) + 1
    other = sum(v for c, v in cnt.items() if c not in ("not_found", "permission_denied", "unreadable"))
    print("\n汇总：扫了 %d 个位置；不存在 %d 个；读不了 %d 个；跳过 %d 个（%s）" % (
        r["_scanned"], cnt.get("not_found", 0), cnt.get("permission_denied", 0) + cnt.get("unreadable", 0),
        other, ", ".join("%s=%d" % kv for kv in sorted(cnt.items())) or "无"))
    for n in r["notes"]:
        print("提示：" + n)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="keysprawl", description="只读、离线地扫描本机 AI / GitHub key 的副本。")
    ap.add_argument("command", nargs="?", choices=["scan"], help="默认就是 scan")
    ap.add_argument("--path", action="append", help="额外扫描这个目录里的 .env*（可多次）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--checklist", metavar="FILE.md", help="把止损清单写到这个文件")
    ap.add_argument("--force", action="store_true", help="允许覆盖已存在的清单文件")
    ap.add_argument("--no-env", action="store_true", help="不检查当前进程环境变量")
    ap.add_argument("--version", action="version", version="keysprawl " + VERSION)
    args = ap.parse_args(argv)
    if args.checklist and os.path.exists(args.checklist) and not args.force:
        print("清单文件已存在，不覆盖（加 --force 才覆盖）：%s" % args.checklist, file=sys.stderr)
        return 2
    try:
        r = run(args)
    except Exception as e:  # never print message/traceback: they could contain file content
        print("内部错误：%s（处理文件：%s）" % (type(e).__name__, CURRENT["path"]), file=sys.stderr)
        return 3
    cl = checklist(r) if args.checklist else None
    if args.json:
        out = {k: v for k, v in r.items() if not k.startswith("_")}
        out["keys"] = [{a: b for a, b in k.items() if a != "provider"} for k in out["keys"]]
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        print_table(r)
    if args.checklist:
        with open(args.checklist, "w", encoding="utf-8") as fh:
            fh.write(cl + "\n")
    return 1 if r["keys"] else 0


if __name__ == "__main__":
    sys.exit(main())
