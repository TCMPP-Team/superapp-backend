# superapp-demo-node-lite

[English](README.md) | 中文

最小 Node.js 实现（HMAC-SHA256 验签 + AES-256-GCM 解密）：仅 `POST /user/checkUser`。零依赖，Node >= 18（推荐 Node 20+ LTS）。

## 项目结构

| 文件 | 作用 |
|---|---|
| `src/server.js` | HTTP 服务与 checkUser 流程：验签 → 解析 body → 解密 → 业务处理 |
| `src/signature.js` | `TC-Signature` 验签（协议实现，请勿修改） |
| `src/identityCrypto.js` | `encryptedData` 解密（协议实现，请勿修改） |
| `src/userStore.js` | 用户查询与 openId 映射存储（**请替换为你自己的实现**） |
| `src/errorCodes.js` | 所有 `returnCode` 定义 |
| `checkUser.json` | `/user/checkUser` 的 OpenAPI 3.0 接口文档，可导入 Swagger / Postman |

## 接入时需替换

`src/userStore.js` 是内存示例实现。保留这两个异步函数，改为对接你自己的存储：

- `findUser(userId)`：在你自己的用户库中查询用户，返回 `true` / `false`。demo 中用户来自 `USERS`。
- `saveOpenIdMapping({ openId, miniAppId, userId })`：持久化 `openId + miniAppId ↔ userId` 映射（openId + miniAppId 为联合唯一键，冲突时覆盖更新）。仅在用户存在、且 `encryptedData` 解密出非空的 `openId` 和 `miniAppId` 时调用。

任一函数抛出异常时服务返回 `50000`。其他意外错误同样返回 `50000`，不会导致进程退出。

## 运行

```bash
SIGN_KEY=0123456789abcdef0123456789abcdef \
DATA_ENCRYPT_KEY=0123456789abcdef0123456789abcdef \
USERS=demo-user-001 npm start     # 默认监听 :9093
npm test
```

Windows（PowerShell）：

```powershell
$env:SIGN_KEY="0123456789abcdef0123456789abcdef"
$env:DATA_ENCRYPT_KEY="0123456789abcdef0123456789abcdef"
$env:USERS="demo-user-001"
npm start
```

启动时如果 `SIGN_KEY` 或 `DATA_ENCRYPT_KEY` 未配置或长度不对，服务会打印警告。

> 上面的密钥是 `npm test` 使用的公开测试密钥。生产环境请使用你在控制台中填写的密钥（见[控制台配置](#控制台配置)），`SIGN_KEY` 与 `DATA_ENCRYPT_KEY` 不要相同，也不要提交到代码仓库。

| 环境变量 | 说明 |
|---|---|
| `SIGN_KEY` | HMAC 签名密钥，16–64 字符（控制台：**Signing key**） |
| `DATA_ENCRYPT_KEY` | AES-256-GCM 数据密钥，必须为 32 字符（控制台：**Data encryption key**） |
| `APPLICATION_ID` | 可选，校验 `TC-ApplicationID`（控制台：**AppID**） |
| `BASE_PATH` | 可选，控制台 **Domain name** 中的路径部分（见[请求路径](#请求路径)）。默认为空，即响应 `/user/checkUser` |
| `SIGNATURE_SKEW_SEC` | 时间戳窗口（秒），默认 300 |
| `USERS` | 用于测试的真实 APP 用户 ID，多个用逗号分隔。请求中的 `userId` 在列表内返回 `true`，否则返回 `false` |

## 控制台配置

在控制台进入 **Configuration management → Backend service configurations**，新增后台服务域名：

| 控制台字段 | 对应 | 说明 |
|---|---|---|
| AppID | 请求头 `TC-ApplicationID` / `APPLICATION_ID` | 由控制台展示，如 `app-xxxxxxxx`，参与签名（StringToSign 第 5 行）。 |
| Signing key | `SIGN_KEY` | 由你填写。HMAC-SHA256 密钥，16–64 字符，仅英文、数字、符号。 |
| Data encryption key | `DATA_ENCRYPT_KEY` | 由你填写。AES-256-GCM 密钥，必须为 32 字符，仅英文、数字、符号。 |
| Domain name | 平台请求 `POST <Domain name>/user/checkUser` | 可以带路径，见[请求路径](#请求路径)。 |

两个密钥都由你自己生成，请随机生成，并在控制台和你的服务端配置**相同的值**。例如：

```bash
openssl rand -hex 24   # Signing key：48 个字符（16–64 字符）
openssl rand -hex 16   # Data encryption key：32 个字符
```

两个密钥都只能包含英文、数字和符号（ASCII）。ASCII 字符在 UTF-8 下 1 个字符 = 1 个字节，所以字符数就是字节数：16–64 字符 = 16–64 字节，`DATA_ENCRYPT_KEY` 的 32 字符正好是 AES-256-GCM 要求的 32 字节。

## 请求路径

平台请求 `<Domain name>/user/checkUser`。**签名使用的 path** 是完整地址去掉 `scheme://host` 后的部分：

**签名 path = 控制台 Domain name 中的路径部分 + `/user/checkUser`**

| 控制台中的 Domain name | 平台实际请求 | 签名 path | `BASE_PATH` |
|---|---|---|---|
| `https://api.example.com` | `https://api.example.com/user/checkUser` | `/user/checkUser` | 不设置（默认） |
| `https://api.example.com/superapp` | `https://api.example.com/superapp/user/checkUser` | `/superapp/user/checkUser` | `/superapp` |
| `https://api.example.com/superapp/inner` | `https://api.example.com/superapp/inner/user/checkUser` | `/superapp/inner/user/checkUser` | `/superapp/inner` |

Domain name 中的路径是可选的，可以是任意值；本文中的 `/superapp/inner` 只是示例。

### 网关转发

如果 Domain name 指向网关，且网关转发时**去掉了路径前缀**，你的服务收到的是 `/user/checkUser`，而平台签名用的是完整路径。可任选一种方式处理：

1. 网关不去掉前缀，原样透传路径；或把原始请求路径放在自定义请求头（如 `X-Original-URI`）中带过来，验签时使用它。
2. 在服务端配置前缀（如 `/superapp/inner`），验签时用 `前缀 + 收到的路径` 作为 path。

本 demo 使用实际收到的路径验签，因此直接支持网关原样透传路径的方式（将 `BASE_PATH` 设为该前缀）。其他方式请将原始路径或拼接后的路径作为 `requestURI` 传给 `src/signature.js` 中的 `buildHmacStringToSign`。

网关不要改写 body 和 query，并保留 `TC-*` 请求头。

## 请求

请求头：

```
TC-Signature:     签名（64 位小写 hex）
TC-Timestamp:     13 位毫秒时间戳
TC-ApplicationID: 应用 ID
TC-TraceID:       链路追踪 ID，在响应中作为 requestId 返回
```

请求体：

```json
{
  "userId": "u1",
  "encryptedData": {
    "algorithm": "AEAD_AES_256_GCM",
    "ciphertext": "base64(ciphertext || tag)",
    "nonce": "base64(12B)"
  }
}
```

- `userId`：你自己的用户 ID（Super App 通过 `setAccount` 设置的 uid）。
- `encryptedData`：加密后的身份信息，见[二、解密 encryptedData](#二解密-encrypteddata)。可选，不传时不解密身份信息。身份信息（`openId` / `miniAppId`）只通过这个字段传递。

## 一、验签

平台发送请求前，按下面的规则计算签名，放在请求头 `TC-Signature` 中。你的服务端收到请求后，用收到的内容按**相同的规则**（第 3～7 步）再计算一次，与 `TC-Signature` 比对（第 8 步），一致即说明请求来自平台且未被篡改。

```
TC-Signature = 小写hex( HMAC-SHA256( key = SIGN_KEY, message = StringToSign ) )
```

**第 1 步：取请求头**

取 `TC-Signature`、`TC-Timestamp`、`TC-ApplicationID`。缺少签名头时返回 `40101`。

**第 2 步：校验时间戳**

`TC-Timestamp` 必须是 13 位毫秒，且与当前时间相差不超过 `SIGNATURE_SKEW_SEC`（默认 300 秒），否则返回 `40102`。

**第 3 步：准备输入**

| 输入 | 来源 |
|---|---|
| `method` | HTTP 方法，大写，如 `POST` |
| `path` | 平台调用的完整路径，见[请求路径](#请求路径)。保持原样：不解码，不处理 `.` 和 `..` |
| `query` | URL 中 `?` 之后的部分；`/user/checkUser` 通常没有 query |
| `applicationId` | 请求头 `TC-ApplicationID` |
| `timestamp` | 请求头 `TC-Timestamp`，原样使用 |
| `body` | **收到的原始请求体字节**。不要先解析 JSON 再序列化 |
| `SIGN_KEY` | 控制台中配置的 Signing key |

**第 4 步：规范化 query**

没有 query 时 `canonicalQuery` 为空串，直接进入下一步。有 query 时：

1. 按 `&` 拆成 `key=value`（缺 `=` 时 value 为空串）。
2. 每个 key、value 先 **URL 解码**（`+` 保持字面量，不当作空格；非法 `%XX` 或非法 UTF-8 视为失败），再 **URL 编码**（保留 `A-Z a-z 0-9 - _ . ~`，其余 UTF-8 字节写成大写 `%XX`，空格为 `%20`）。
3. 按 key 的字节序排序，key 相同再按 value 排序。
4. 用 `&` 连接成 `canonicalQuery`。

例：`?name=%E5%BC%A0%20%E4%B8%89&b=2&a=1&a=0` → `a=0&a=1&b=2&name=%E5%BC%A0%20%E4%B8%89`

**第 5 步：计算 body 哈希**

```
bodyHash = 小写hex( SHA-256( body ) )
```

空 body 的哈希为 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`。

**第 6 步：拼接 StringToSign**

固定 7 行，用 `\n` 连接，**末尾再补一个 `\n`**：

| 行 | 内容 |
|---|---|
| 1 | `TC-SIGN-V1:P2S`（固定值） |
| 2 | `method` |
| 3 | `path` |
| 4 | `canonicalQuery`（没有 query 时为空行，**这一行仍然存在**） |
| 5 | `applicationId` |
| 6 | `timestamp` |
| 7 | `bodyHash` |

```
StringToSign = "TC-SIGN-V1:P2S\n" + method + "\n" + path + "\n" + canonicalQuery + "\n"
             + applicationId + "\n" + timestamp + "\n" + bodyHash + "\n"
```

**第 7 步：生成签名**

```
signature = 小写hex( HMAC-SHA256( SIGN_KEY, StringToSign ) )   // 64 位小写 hex
```

**第 8 步：比对**

将 `signature` 与请求头 `TC-Signature` 做常量时间比较，只接受 64 位小写 hex。一致即验签通过，否则返回 `40101`。

### 代码（完整实现见 `src/signature.js`）

```js
import crypto from 'node:crypto';

function sign({ secret, method, path, canonicalQuery, applicationId, timestamp, body }) {
  const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
  const stringToSign = [
    'TC-SIGN-V1:P2S', method, path, canonicalQuery, applicationId, timestamp, bodyHash,
  ].join('\n') + '\n';
  return crypto.createHmac('sha256', secret).update(stringToSign).digest('hex');
}
```

### 自测示例

下面的 `/superapp/inner` 只是示例前缀，实际签名 path 取决于你在控制台填写的 Domain name。

| 项 | 值 |
|---|---|
| SIGN_KEY | `0123456789abcdef0123456789abcdef` |
| 请求 | `POST /superapp/inner/user/checkUser`，无 query |
| TC-ApplicationID | `app-demo001` |
| TC-Timestamp | `1721234567890` |
| Body | `{"userId":"user-001","encryptedData":{"algorithm":"AEAD_AES_256_GCM","ciphertext":"VsfUDLx2m8iK5lPRJL+XPJNFdsZ28yvGEqzD1ol0lf7zwWF7GoN4Mr0H1jW0xYJKXKL50zKS+KtGKhkqeXZwTp0zRkyqUHz7FpxuQy1JTZh+LJDU","nonce":"AAECAwQFBgcICQoL"}}` |
| bodyHash | `de5522bc02375469f4577ad87e0a0d2ff95449282b6de8231b8dea5fba7dc538` |
| StringToSign | `TC-SIGN-V1:P2S\nPOST\n/superapp/inner/user/checkUser\n\napp-demo001\n1721234567890\nde5522bc02375469f4577ad87e0a0d2ff95449282b6de8231b8dea5fba7dc538\n` |
| TC-Signature | `979d739e66a1e2709f855e829f50d146ac825e6c140dbef3a1df4cdbe042f59f` |

## 二、解密 encryptedData

**第 1 步：取字段**

从请求体的 `encryptedData` 中取 `algorithm`、`ciphertext`、`nonce`。`algorithm` 必须为 `AEAD_AES_256_GCM`，其他值都会被拒绝。这只是协议中的算法标识，实际算法是标准的 AES-256-GCM。

**第 2 步：Base64 解码**

`ciphertext`、`nonce` 都是标准 Base64（非 URL-safe）。`nonce` 解码后为 12 字节，每次请求随机生成。

**第 3 步：拆分密文与 tag**

`ciphertext` 解码后，最后 16 字节是 GCM tag，前面是密文。

**第 4 步：AES-256-GCM 解密**

- key：`DATA_ENCRYPT_KEY`（32 字符）
- iv：解码后的 `nonce`
- tag：第 3 步的 16 字节
- **不使用 AAD**（不传、`nil`、空串、长度为 0 的字节数组结果一致；传任何非空 AAD 都会认证失败）

**第 5 步：解析明文**

明文为 JSON：`{"openId":"...","miniAppId":"..."}`。

```js
import crypto from 'node:crypto';

function decryptEncryptedData(env, key /* 32 字节 Buffer */) {
  const sealed = Buffer.from(env.ciphertext, 'base64');
  const nonce = Buffer.from(env.nonce, 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  d.setAuthTag(sealed.subarray(sealed.length - 16));
  const plain = Buffer.concat([d.update(sealed.subarray(0, sealed.length - 16)), d.final()]);
  return JSON.parse(plain.toString('utf8'));   // { openId, miniAppId }
}
```

完整实现（含输入校验）见 `src/identityCrypto.js`。任何解密失败都返回 `40101`。

### 自测示例

| 项 | 值 |
|---|---|
| DATA_ENCRYPT_KEY | `0123456789abcdef0123456789abcdef` |
| nonce | `AAECAwQFBgcICQoL` |
| ciphertext | `VsfUDLx2m8iK5lPRJL+XPJNFdsZ28yvGEqzD1ol0lf7zwWF7GoN4Mr0H1jW0xYJKXKL50zKS+KtGKhkqeXZwTp0zRkyqUHz7FpxuQy1JTZh+LJDU` |
| 解密结果 | `{"openId":"oUpF8uMuAJO_M2pxb1Q9zNjWeS6o","miniAppId":"mini-demo001"}` |

## 响应

`{"returnCode":"0","returnMessage":"OK","data":true|false,"requestId":"..."}`

`requestId` 透传 `TC-TraceID`（请求中没有时随机生成）。

| 场景 | returnCode | data |
|---|---|---|
| 用户存在 | `"0"` | `true` |
| 用户不存在（业务结果，不是失败） | `"0"` | `false` |
| 参数非法 / 缺少 `userId` | `"40001"` | `null` |
| 验签失败 / 身份信息解密失败 | `"40101"` | `null` |
| 时间戳超出窗口 | `"40102"` | `null` |
| 本端 `SIGN_KEY` / `DATA_ENCRYPT_KEY` 未配置 / 内部错误 | `"50000"` | `null` |

## 常见问题

| 现象 | 原因 |
|---|---|
| `404 not found` | 请求路径不是 `<BASE_PATH>/user/checkUser`；请将 `BASE_PATH` 设为控制台 Domain name 中的路径部分 |
| 一直 `40101` | body 被框架重新序列化，哈希与原始字节不一致 |
| 经过网关 / 代理后一直 `40101` | 网关去掉或修改了路径前缀，见[网关转发](#网关转发) |
| 第 4 行丢失 | 没有 query 时漏了空行，StringToSign 少一个 `\n` |
| 末尾缺 `\n` | StringToSign 最后一行也要以 `\n` 结尾 |
| 签名大小写不符 | 只接受小写 hex |
| `40102` | 时钟偏差超过窗口，或时间戳不是 13 位毫秒 |
| query 含 `+` 时验签失败 | `+` 是字面量，不是空格，应编码为 `%2B` |
| `40101 identity decrypt failed` | `DATA_ENCRYPT_KEY` 与控制台中的不一致，或 `algorithm` 不是 `AEAD_AES_256_GCM` |
| `50000 server misconfigured` | `SIGN_KEY` 不是 16–64 字符，或 `DATA_ENCRYPT_KEY` 不是 32 字符；请查看启动时的警告 |

## 接口文档（checkUser.json）

`checkUser.json` 是 `POST /user/checkUser` 的 OpenAPI 3.0 描述，包括请求头、请求体、字段规则，以及每种 `returnCode` 的示例。开发你自己的接口时可以作为接口参考。

- **Swagger**：在 [Swagger Editor](https://editor.swagger.io) 中打开（File → Import file），或导入任意 Swagger UI。
- **Postman**：Import → 选择 `checkUser.json`。将 server 变量 `host` / `basePath` 改为你的服务地址。

`TC-Signature` 需要根据当前时间戳、路径和原始 body 每次实时计算，因此示例请求不能直接发送：示例时间戳已超出时间窗口，会返回 `40102`。如需在本地验证完整流程，请运行 `npm test`。
