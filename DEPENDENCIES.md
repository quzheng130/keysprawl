# 依赖清单

| 包 | 用途 | 许可证 | 随工具发布？ |
|---|---|---|---|
| Python 标准库（argparse、json、re、sqlite3、os、pathlib 等） | 运行时 | PSF-2.0 | 是（用户自带 Python 3.9+） |
| SQLite（经 Python `sqlite3` 模块） | 只读打开 OpenCode v2 凭据库 | 公有领域（Public Domain） | 是（随 Python 提供） |
| pytest | 验收测试 | MIT | 否，只在开发时用 |

运行时零第三方依赖，不导入任何网络库（`socket`、`http`、`urllib`、`ssl` 等）。没有引用、复制或链接 gitleaks / trufflehog / OpenCode 的代码或规则文件。
