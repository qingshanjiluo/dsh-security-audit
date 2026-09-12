# dsh-security-audit

> DeepSeek Harness 安全审计

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ✨ 功能特性

- 🔍 **依赖漏洞扫描**: 检测项目依赖中的已知安全漏洞
- 🔑 **密钥检测**: 200+ 密钥模式检测，防止敏感信息泄露
- 📜 **许可证合规**: 检查依赖许可证合规性
- 📖 **Git 历史扫描**: 扫描 Git 历史中的敏感信息
- 📊 **风险评分**: 0-100 综合风险评分系统

## 📦 安装

```bash
npm install dsh-security-audit
```

## 🛠️ 工具

| 工具名 | 描述 | 参数 |
|--------|------|------|
| `security_audit` | 全面安全审计 | `scanType`（扫描类型）、`projectDir`（项目目录） |
| `scan_secrets` | 快速密钥扫描 | `path`（扫描路径） |

## 📋 命令

- `/audit` — 执行安全审计

## ⚙️ 配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enabled` | boolean | `true` | 启用插件 |
| `scanSecrets` | boolean | `true` | 扫描密钥 |
| `scanVulnerabilities` | boolean | `true` | 扫描漏洞 |
| `checkLicenses` | boolean | `true` | 检查许可证 |
| `maxFileSize` | number | `1048576` | 最大扫描文件大小（字节） |

## 📄 License

MIT
