# dsh-security-audit

> DeepSeek Harness 安全审计插件

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ✨ 功能特性

- 🔒 **漏洞扫描**: npm audit / pip-audit / govulncheck / cargo audit 多生态支持
- 🔑 **密钥检测**: 200+ 正则模式，覆盖 AWS/GitHub/Slack/Stripe/数据库连接串
- 📜 **许可证合规**: GPL/AGPL/SSPL 限制性许可证检测
- 📂 **Git 历史扫描**: 检测已删除的敏感文件和可疑提交信息
- 📊 **风险评分**: 0-100 综合安全评分 + 修复建议

## 📦 安装

```bash
npm install dsh-security-audit
```

## 🛠️ 工具

| 工具名 | 描述 | 参数 |
|--------|------|------|
| `security_audit` | 全面安全审计 | `scanType`(all/secrets/vulns/licenses), `projectDir` |
| `scan_secrets` | 快速密钥扫描 | `path`(扫描路径) |

## 📋 命令

- `/audit` — 执行全面安全审计

## ⚙️ 配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enabled` | boolean | `true` | 启用插件 |
| `scanSecrets` | boolean | `true` | 扫描密钥泄露 |
| `scanVulnerabilities` | boolean | `true` | 扫描依赖漏洞 |
| `checkLicenses` | boolean | `true` | 检查许可证合规 |
| `maxFileSize` | number | `102400` | 最大扫描文件大小(bytes) |

## 📄 License

MIT
