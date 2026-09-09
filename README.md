# jumpserver-mcp

JumpServer (KoKo) 堡垒机连接器，以 **MCP stdio Server** 形式接入 WorkBuddy（自定义连接器）。由 `dsh-jumpserver`（DSH 插件，v0.3.1）移植：核心层（`jumpserver/` 状态机会话、`security/` 权限闸门与审计）原样复用，DSH 宿主依赖（cordis / dsh-credentials / dsh-storage-domain / dsh-better-sidebar）替换为 MCP + 环境变量 + JSONL 审计文件。

## 工具（10 个）

| 工具 | 作用 |
|---|---|
| `jumpserver_status` | 查询会话状态 / 网关 / 当前目标 / 权限模式 |
| `jumpserver_connect` | 建立持久 SSH/PTY 会话，等待 KoKo 菜单 |
| `jumpserver_enter` | 经 KoKo 菜单进入目标资产（探针验证后才算进入） |
| `jumpserver_assets` | 抓取授权资产列表（`p` 只读命令 + footer 校验 + 缓存） |
| `jumpserver_exec` | 在当前已进入资产上执行一条简单命令 |
| `jumpserver_run` | 自动导航 + 验证 + 执行（单目标单命令） |
| `jumpserver_batch` | 多目标多命令批量执行（target affinity） |
| `jumpserver_leave` | 退出当前资产回 KoKo 菜单 |
| `jumpserver_close` | 关闭会话释放资源 |
| `jumpserver_snapshot` | 终端镜像：读取最近 PTY 事件流（供对话内渲染终端视图） |

安全设计与原插件一致：显式状态机（非法迁移落 `UNKNOWN`）、命令静态分类（READ / PRIVILEGED_READ / UNKNOWN / MODIFY / DANGEROUS）、READ_ONLY 默认、审计落盘（不含凭据）、密码按连接解析不缓存。

## 配置

1. `config.example.json` 复制为 `config.json`，填 `host` / `username`。
2. 密码走环境变量（`passwordEnv`，默认 `JUMPSERVER_PASSWORD`），在 `~/.workbuddy/mcp.json` 的 `env` 中注入；不要写进 config.json。

## 注册到 WorkBuddy

编辑 `~/.workbuddy/mcp.json`（保留已有 server）：

```json
{
  "mcpServers": {
    "jumpserver": {
      "type": "stdio",
      "command": "node",
      "args": ["C:/Users/****/WorkBuddy/jumpserver-mcp/lib/server.js"],
      "env": { "JUMPSERVER_PASSWORD": "..." },
      "description": "JumpServer 堡垒机连接器：持久会话、资产发现、权限闸门、命令审计"
    }
  }
}
```

保存后在 WorkBuddy 连接器管理中对 `jumpserver` 点击「信任」启用（新连接器需重启客户端后出现）。

## 审批流（MCP 惯用法）

READ_ONLY 下只读命令直接执行；MODIFY / DANGEROUS / UNKNOWN 命令首次调用返回 `COMMAND_APPROVAL_REQUIRED` + 脱敏审批原因 → Agent 把原因展示给用户 → 用户同意后 Agent 以 `confirm: true` 重试同一调用。WorkBuddy 的连接器工具确认弹窗是外层闸门；`requireArm: true` 可再叠加 30 分钟授权模式（`jumpserver_arm/disarm`）。

## 构建

```bash
npm install
npm run build
npm run smoke   # JSON-RPC over stdio 冒烟（initialize + tools/list + status）
```
