# Changelog

## 0.1.0（2026-10-29）
首个版本。曾用名 keyscan，因重名改名为 keysprawl。

- 只读扫描本机常见位置里的 OpenAI、Anthropic、GitHub key：OpenCode（`auth.json`、v2 `opencode.db`、`opencode.json`）、Claude Code（`settings.json`、`.credentials.json`、`~/.claude.json`）、Codex（`auth.json`、`config.toml`）、shell 启动文件、PowerShell profile、`.env*`（递归最多 4 层）、这些文件的 `.bak/.old/~/.orig` 备份，以及 6 个常见环境变量。
- 支持 `XDG_DATA_HOME`、`OPENCODE_DB`、`CLAUDE_CONFIG_DIR`、`CODEX_HOME`。
- 同一个 key 按物理文件（设备 + inode）计副本数，符号链接作为别名列出。
- 输出只显示掩码（前缀 + 末 4 位）；支持表格、`--json` 和 `--checklist` 止损清单。
- SQLite 库以只读、不可变模式打开；运行时不联网，只用 Python 标准库。
- 退出码：0 没发现 key，1 发现 key，2 参数错误或清单文件已存在，3 内部错误。
- 附带 pytest 测试和一个在断网命名空间 + strace 下运行的检查脚本（`tests/at7_check.sh`），以及对应的 GitHub Actions 工作流。
