# EonAI Proof Verifier

在客户自己的浏览器中核验 API 响应的官方来源、签名和完整性。无需 API Key，没有响应上传、遥测或第三方脚本。在线入口：https://eonaibusiness.com/verify/

这是基于公开 Proof-of-Observation 协议的独立验证界面，不是 EonAI 自行运行的 Nitro enclave，也不是独立生成的硬件证明。本项目验证供应商随响应交付的证据。代码来源及修改记录见 [NOTICE](NOTICE.txt)，许可见 [LICENSE](LICENSE) 和 [LICENSE-APACHE](LICENSE-APACHE)。

## 客户使用

1. 用中转站客户令牌调用 `https://api.eonaibusiness.com/verified/response/v1/messages`，模型 `claude-opus-5-5`，`stream: true`，`max_tokens` 1–8192。
2. 将完整 SSE 响应保存为原始字节，必须包含正文和最后的 `event: tee.proof`。Windows 使用 `curl.exe -o response.sse`，不要用 PowerShell 重定向改写编码。
3. 打开验证页面选择文件或粘贴完整响应。材料在本机处理，不需要把客户令牌交给验证器。
4. 也可下载本仓库的 `verify-offline.html`，断网后直接在浏览器打开。它自包含所有代码，不请求远程资源。

响应验证检查 AWS Nitro G1 根证书链、当前证书有效期、可信 PCR0、公钥绑定、nonce 一致性、官方 host/path、Ed25519 签名、响应 SHA-256、原生模型字段和完整结束事件。任何失败都不能标为通过。

## 可验证范围

默认是 **response-only（来源与响应）**。可选上传自己实际发送的原始请求文件，额外检查请求 SHA-256，全部匹配才算 full。当前供应商实测原始请求哈希不一致，所以完整请求验证会失败；响应验证成功不能被写成请求未修改。

本项目不证明内部模型权重或模型质量，不保证明文保密。请求头和 query 不在签名覆盖中；nonce 一致性不能完全解决相同请求之间的旧响应重放。证明、度量值和源代码也可能用于识别证明提供者，不承诺供应链匿名。

## 可信参考值

`policy.js` 固定预期官方 host、模型和 PCR0，绝不从上传的 proof 自动采纳参考值。当前 PCR0：

```
437cbab8c2e5dd11a35ae5b062fe115623a013910b7c26b333e2b3af477944d630fb1dcd76fa9a9b1eefdf1d1021dec2
```

来源：[proof-of-observation 的公开参考值和复现说明](https://github.com/focuxdot/proof-of-observation#why-you-can-trust-the-pcr0)，对应测量源码 `03fe2a3eb6d05e1ec94f7f52ac0521d42560a731`。本次实测 attestation 与公布值相符；EonAI 尚未独立复现 EIF 构建，不把上游声明写成独立审计结论。用户可以自己复现或核对可信公开发布。AWS 根指纹以 [AWS 官方说明](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)为独立信任来源。

## 代码与测试

- `verifier.js`：有界 CBOR/DER、浏览器 WebCrypto 和 SSE 字节核验。
- `policy.js`：独立配置的参考值。
- `app.js`、`index.html`、`style.css`：EonAI 界面，无供应商营销或调用入口。
- `verify-offline.html`：自包含离线版本；使用 `node build-offline.mjs` 从相同源码生成。

使用 Node 24+ 运行 `npm test`。测试中使用的合成签名不是硬件证明，合成材料不能通过真实硬件校验。真实证据应来自你自己捕获的调用响应，不在仓库发布账户、客户材料、网关账本或供应商密钥。
