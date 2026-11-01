# keysprawl

Read-only, offline scan that finds copies of your OpenAI, Anthropic and GitHub keys across local coding-agent configs, shell rc and .env files. Output is masked.

只读、不联网地扫一遍本机，找出 OpenAI / Anthropic / GitHub key 散落在哪些 coding agent 配置、`.env`、shell 启动文件和备份里，每个 key 有几份副本，并生成一页止损清单。输出里只有掩码（如 `sk-proj-…a1B2`），不会显示完整 key。

> 状态：v0.1.0，未发布。

## 它做什么、不做什么
- 做：读取本机文件和当前进程的环境变量，列出 key 的类型、掩码、副本数和位置；可输出 JSON 或止损清单。
- 不做：不联网、不验证 key 是否有效、不吊销或替换 key、不修改任何被扫文件、不读系统钥匙串、不扫 git 历史。

## 安装和运行
只需要一个 `keysprawl.py` 文件和 Python 3（代码按 3.9+ 写，目前只在 Python 3.13 / Linux 上测试过）。没有第三方依赖。

### macOS / Linux
```bash
python3 --version          # 确认有 Python 3
python3 keysprawl.py         # 扫默认位置 + 当前目录的 .env*
python3 keysprawl.py --json
python3 keysprawl.py --path ~/code --checklist ~/keysprawl-checklist.md
```

### Windows（PowerShell）
```powershell
py --version
py keysprawl.py
py keysprawl.py --json
py keysprawl.py --path $HOME\code --checklist $HOME\keysprawl-checklist.md
```
（Windows 和 macOS 还没有在实机上测过。）

### 参数
| 参数 | 作用 |
|---|---|
| `scan`（可省略） | 扫描 |
| `--path DIR` | 额外扫这个目录里的 `.env*`，最多 4 层，可写多次 |
| `--json` | 输出 JSON |
| `--checklist FILE.md` | 写止损清单；文件已存在就报错，加 `--force` 才覆盖 |
| `--no-env` | 不检查当前进程的环境变量 |
| `--version` / `--help` | 版本 / 帮助 |

退出码：0 没发现 key；1 发现 key；2 参数错误或清单文件已存在；3 内部错误。

### 扫哪些位置
OpenCode（`~/.local/share/opencode/auth.json`、`opencode.db`、`~/.config/opencode/opencode.json`、项目里的 `opencode.json`），Claude Code（`~/.claude/settings.json`、`.credentials.json`、`~/.claude.json`、项目 `.claude/settings*.json`），Codex（`~/.codex/auth.json`、`config.toml`），shell 启动文件，PowerShell profile，以上文件的 `.bak/.old/~/.orig` 备份，`.env*`。支持 `XDG_DATA_HOME`、`OPENCODE_DB`、`CLAUDE_CONFIG_DIR`、`CODEX_HOME`。SQLite 库用只读、不可变模式打开。

### 开发者：跑测试
```bash
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/pytest -v tests
```
测试用的假 key 在运行时随机生成，只写进临时目录。

## 这个工具回应了哪些用户反馈
| # | 用户的投诉 | keysprawl 怎么回应 | 来源 |
|---|---|---|---|
| 1 | OpenCode 官方通知：工作区里保存的第三方 provider key（如 OpenAI、Anthropic）可能已泄露，请去各家后台吊销、替换并更新所有用到它们的应用 | keysprawl 列出这些 key 在本机还有哪些副本，清单直接给 OpenAI / Anthropic 后台链接和要改的本机位置 | [HN 50133412](https://news.ycombinator.com/item?id=50133412) |
| 2 | 泄露后“大家都收到邮件，每个人只能自己动手” | keysprawl 不替你吊销，但把“自己动手”变成一页逐项打勾的清单：吊销 → 新建 → 改完每个位置 → 查用量 | [HN 50133904](https://news.ycombinator.com/item?id=50133904) |
| 3 | OpenCode v2 里 `opencode.db` 的 `credential` 表会悄悄压过配置里的 apiKey，一次性导入后再改 `auth.json` 也不生效，换 key 后还在用旧 key | keysprawl 同时扫 `auth.json`、`opencode.json` 和只读打开的 `opencode.db`，换 key 后再跑一次就能看出哪里还留着旧 key（掩码末 4 位不同）。是否能完全对上该问题的所有场景：INFERENCE | [GitHub #58394](https://github.com/anomalyco/opencode/issues/58394) |
| 4 | 泄露受害者说 API 上被刷走 $400，发邮件一周没人回 | keysprawl 不能追回损失；清单把“去后台看近期用量”和“新 key 设花费上限”列为固定步骤，帮人尽早止损（效果是 INFERENCE） | [GitHub #58680](https://github.com/anomalyco/opencode/issues/58680) |
| 5 | 有人想找本地离线的工具，因为听说 OpenCode 安全上松、默认会回传数据 | keysprawl 运行时不导入任何网络库、没有遥测和自动更新、不常驻；源码一个文件，可以自己审 | [HN 50228456](https://news.ycombinator.com/item?id=50228456) |

## 许可证
MIT，见 `LICENSE`。依赖见 `DEPENDENCIES.md`。
