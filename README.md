{
  "name": "dsh-security-audit",
  "version": "1.0.0",
  "description": "DeepSeek Harness 安全审计插件 — 依赖漏洞扫描、密钥泄露检测、许可证合规检查",
  "features": [
    "多语言依赖漏洞扫描（npm/pip/govulncheck/cargo）",
    "200+ 正则模式的密钥泄露检测（AWS/GitHub/Slack/Stripe/数据库等）",
    "许可证合规检查（GPL/AGPL/SSPL 等限制性许可证检测）",
    "综合风险评分（0-100）和修复建议",
    "注册 slash 命令 /audit",
    "设置页面配置（启用/各模块开关）",
    "支持快速密钥扫描工具 scan_secrets"
  ],
  "keywords": ["deepseek-harness", "dsh-plugin", "security", "audit", "vulnerability", "secret-scanner", "license"],
  "author": "",
  "license": "MIT"
}
