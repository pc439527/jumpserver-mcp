# 工单：MCP 工具参数在客户端侧被 AJV 误判为类型错误（batch/compare/inspect 全线退化）

| 项目 | 内容 |
|---|---|
| 工单号 | （待平台侧分配） |
| 报告人 | Kinder Ou（SAP BASIS / IT 基础建设部） |
| 报告日期 | 2026-10-22 |
| 影响组件 | WorkBuddy 宿主 CLI / 桌面端 MCP 调用层（`validateParams`） |
| 严重级别 | 高 —— 直接导致 MCP 连接器的批量类工具不可用 |
| 关联连接器 | `jumpserver-mcp` v0.6.1（本仓库已做连接器侧兜底） |

---

## 1. 现象

调用 `jumpserver-mcp` 的批量类工具时，参数在**尚未发往 MCP 服务端**之前就被客户端拒绝：

```
Parameter validation failed for tool "jumpserver_batch": /tasks(targets): must be array
```

统计（`服务器采集` 场景，同一 schema、同一参数）：

| 工具 | 失败 / 总计 |
|---|---|
| `jumpserver_batch` | 3 / 3 |
| `jumpserver_compare` | 4 / 4 |
| `jumpserver_inspect` | 6 / 7 |

**关键对照**：同样的 `targets: ["192.168.30.53"]` 有一次**成功返回**。
⇒ schema 本身合法，是**偶发降级**，不是必现的 schema 错误。

嵌套深度也不固定（`2026-10-21` 记录）：单层、双层、三层嵌套的数组参数**均报错**。

---

## 2. 根因（已定位到代码）

### 2.1 校验发生在客户端

宿主在**发出 MCP 调用之前**用 AJV 校验参数，位置：

```
D:/appfolder/workbuddy/resources/app.asar.unpacked/cli/dist/codebuddy-lite-wb.mjs
偏移 5994979 附近
```

```js
async validateParams(t, i, s) {
  if (i && "object" == typeof i) {
    if (!this.ajv) {
      this.ajv ??= new Ajv({ allErrors: !0, coerceTypes: !0 })
    }
    try {
      let n = this.validateCache.get(s)
      if (n || (n = this.ajv.compile(i), this.validateCache.set(s, n)), !n(t)) {
        let t = n.errors?.map(t => `${t.instancePath || "root"}: ${t.message}`).join("; ")
        return {
          content: `Parameter validation failed for tool "${s}": ${t}\n\nExpected parameter schema:\n${c}\n\nPlease adjust the params to match the schema and try again.`,
          error: `Validation failed: ${t}`
        }
      }
    } catch (t) {
      this.logger.warn(`[cbc-kw=TOOL] DeferExecuteTool: schema validation skipped for "${s}": ${t}`)
    }
  }
}
```

### 2.2 `coerceTypes: true` 不会把 string 变成 array

`coerceTypes: true` 只启用 **number 模式**的强转（string→number / number→string），**不含** string→array。

用同版本 ajv（8.20.0）实测：

| schema | 输入 | 结果 |
|---|---|---|
| `{type:'array', items:{type:'string'}}` | `"1.1.1.1,2.2.2.2"` | ❌ `must be array` |
| `{type:'array', items:{type:'string'}}` | `["1.1.1.1"]` | ✅ |
| `{anyOf:[{type:'array'…},{type:'string'}]}` | `"1.1.1.1,2.2.2.2"` | ✅ |

### 2.3 措辞佐证

- AJV 的类型错误措辞是 **`must be array`**；
- zod 的措辞是 `Expected array, received string`。

报告中的文案是 `must be array` ⇒ **确属 AJV（客户端）**，而非 MCP SDK 的 zod 校验。
SDK 的 zod 校验发生在**服务端**，文案固定为
`Input validation error: Invalid arguments for tool X: <zod message>`，与现象不符。

---

## 3. 结论

失败发生在**客户端参数校验层**，请求**从未到达 MCP 服务端**。
因此任何"服务端做降级/兼容"的改动都无法单独解决这个问题 —— 服务端根本收不到这次调用。

---

## 4. 建议修复（按优先级）

### 方案 A（推荐）：客户端在强转失败时不要中断调用

对 MCP 工具参数，把 AJV 从「拒绝」降级为「告警 + 放行」：

- 校验结果仅用于**提示**，不阻断调用；服务端自己的 schema 校验才是权威闸门；
- MCP 协议本身已有服务端校验（`McpServer.validateToolInput`），客户端重复校验属于**双重校验**，且客户端这份更容易出错（它拿到的是序列化后的形态，不一定是调用者的原始意图）。

风险：会放宽对**非 MCP 内置工具**的保护。建议只对 `mcp__*` 前缀的工具放宽。

### 方案 B：序列化层保形

在生成 `params` 的环节确保数组不被降级为字符串/嵌套数组：

- 检查 `JSON.stringify` 前是否存在 `Array.isArray` 丢失、`args` 被 `String()` 化、或把整个 `params` 二次序列化（`normalizeParams` 里已有 `JSON.parse` 兜底，但仅对顶层字符串生效）；
- 对 `tasks`/`targets` 这类**数组元素本身是对象**的字段，`JSON.parse` 一次即可恢复，不需要嵌套。

### 方案 C：开启 ajv 的 array 强转

若方案 A 不可行，至少把校验器改为能容忍"数组被序列化成字符串"：

```js
new Ajv({ allErrors: true, coerceTypes: true, allowUnionTypes: true })
```
并在编译前把字符串形式的 schema 放宽为 `anyOf: [原 schema, {type:'string'}]`。

---

## 5. 连接器侧已做的兜底（不等本工单）

`jumpserver-mcp` v0.6.1 已让**发布的 JSON Schema 本身**接受字符串：

```json
"targets": {
  "anyOf": [
    { "type": "array", "items": { "type": "string" }, "minItems": 1, "maxItems": 20 },
    { "type": "string" }
  ]
}
```

这样客户端的 AJV 闸门放行 string，服务端再由 `z.preprocess` 归一为数组（并对**归一后**的列表重新施加 min/max 边界，避免字符串形态绕过边界校验）。

已加回归测试（`tests/runtime/arg-normalize.test.mjs`、`tests/runtime/arg-shape-e2e.test.mjs`），用宿主同版本 ajv 复现闸门并断言两种形态均通过。

> 但这只解决「schema 声明为数组、客户端却发来字符串」这一种降级形态。
> 若客户端把数组**嵌套**下发（`[[...]]`）或改变元素类型，本兜底无法覆盖，仍需本工单的方案 A / B。

---

## 6. 复现步骤

1. 在 WorkBuddy 中连接 `jumpserver-mcp`；
2. 调用 `jumpserver_inspect`，`targets` 传 `"1.1.1.1,2.2.2.2"`；
3. 观察返回中出现 `Parameter validation failed for tool "jumpserver_inspect"`；
4. 对照：把 `targets` 传 `["1.1.1.1","2.2.2.2"]` 则可成功进入服务端（无配置时报 `CONFIG_INCOMPLETE`，说明已越过校验层）。

---

## 7. 附：定位命令

```bash
# 找到校验器
grep -a -b -o "Parameter validation failed" \
  "D:/appfolder/workbuddy/resources/app.asar.unpacked/cli/dist/codebuddy-lite-wb.mjs"

# 确认 coerceTypes 配置
grep -a -o "coerceTypes" \
  "D:/appfolder/workbuddy/resources/app.asar.unpacked/cli/dist/codebuddy-lite-wb.mjs"
```

注：桌面端 `app.asar` 内 `must be array` 的命中点均属 axios / uuid 库，**与本问题无关**；真正的校验器在 CLI 分发包 `app.asar.unpacked/cli/dist/codebuddy-lite-wb.mjs`。
