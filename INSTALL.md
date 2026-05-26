# iida-mcp ARM64/idapro stdio 版本安装说明

这个包包含 IDA GUI 插件和 stdio MCP 自动启动入口。

## 环境要求

- IDA Professional，包含 `idapro/idalib`
- `idapy` 或 `idapy.cmd` 已加入 PATH
- Node.js 18 或更新版本
- IDA Python 依赖：

```powershell
idapy -m pip install capstone keystone-engine
idapy -m pip install "D:\\xxx\\idalib\\python\\idapro-0.0.7-py3-none-any.whl"
idapy "D:\\xxx\\idalib\\python\\py-activate-idalib.py" -d "D:\\xxx"
```

## 安装 IDA GUI 插件

把这些文件复制到 IDA 的 `plugins` 目录：

```text
iida.py
iida_core\
```

例如：

```text
D:\\xxx\\plugins\\
```

复制后打开 IDA，从菜单启动插件：

```text
Edit > Plugins > iida-mcp
```

GUI 插件保留原来的 iida 多 IDA HTTP 路由行为。

## 安装 stdio 自动启动 CLI

从发布包安装 npm CLI：

```powershell
npm install -g .\dist\iida-mcp-arm64-stdio-0.4.1-arm64.1.tgz
```

如果你是在解压后的源码目录里安装，也可以运行：

```powershell
npm install -g .
```

这会把 `iida-mcp-stdio` 安装到全局 Node 目录。默认使用 PATH 中的 `idapy.cmd`/`idapy`；只有需要指定另一套 IDA Python 时才传 `--idapy <path>`。

## Codex MCP 配置

```toml
[mcp_servers.iida]
type = "stdio"
command = "iida-mcp-stdio"
args = [
  "--ready-timeout-sec", "180",
  "--keepalive-sec", "86400"
]
startup_timeout_sec = 30
tool_timeout_sec = 210
```

Codex 连接后，运行时调用 `iida_open_file` 打开目标：

```json
{
  "path": "D:\\xxx\\libTarget.so",
  "ready_timeout_sec": 180
}
```

目标打开前，stdio MCP 只暴露：

- `iida_open_file`
- `iida_status`
- `iida_close_file`

目标注册后，`list_files`、`get_info`、`parse_elf`、`list_functions`、`decompile`、`disasm_bytes` 等原 iida 工具会自动出现在同一个 MCP 连接里。

## 注意

- stdio 入口随插件发布，但不运行在 IDA GUI 插件进程里。它必须在 IDA 外部运行，MCP 客户端才能按需启动 IDA/idapro。
- `ready_timeout_sec = 180` 是三分钟 ready 规则。大文件首次建库可能无法在 180 秒内完成，此时会返回明确失败；需要完整首次分析时可以复用已生成 IDB 或增大超时。
- `tool_timeout_sec` 应大于 `ready_timeout_sec`，这样 MCP 客户端能收到明确 ready 错误，而不是自己先超时。
