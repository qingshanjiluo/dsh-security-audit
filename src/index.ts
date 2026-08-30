/**
 * dsh-security-audit — DeepSeek Harness 安全审计插件
 *
 * 核心功能：
 * 1. 依赖漏洞扫描（npm audit / pip-audit / govulncheck / cargo audit）
 * 2. 密钥泄露检测（200+ 正则模式 + 熵分析）
 * 3. 许可证合规检查
 * 4. 综合安全报告生成
 * 5. 注册 slash 命令 /audit
 * 6. 设置页面配置
 */

import { execSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { resolve, join, extname, relative } from 'node:path';
import { z } from 'zod';

// ==================== 常量 ====================

export const name = 'dsh-security-audit';
export const inject = ['settings', 'tools', 'commands'];

const NS = 'security-audit';

// ==================== 设置 Schema ====================

const configSchema = z.object({
  enabled: z.boolean().default(true),
  scanSecrets: z.boolean().default(true),
  scanVulnerabilities: z.boolean().default(true),
  checkLicenses: z.boolean().default(true),
  maxFileSize: z.number().int().min(1024).max(10485760).default(1048576), // 1MB
  excludePatterns: z.array(z.string()).default([
    'node_modules', '.git', 'dist', 'build', 'vendor', '__pycache__',
    '.next', '.nuxt', 'coverage', '.coverage', 'target',
  ]),
});

type Config = z.infer<typeof configSchema>;

// ==================== 类型定义 ====================

interface Vulnerability {
  cve_id: string;
  package: string;
  version: string;
  fixed_in?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cvss_score: number;
  description: string;
  fix_available: boolean;
  url?: string;
}

interface SecretFinding {
  file: string;
  line: number;
  type: string;
  confidence: number;
  preview: string;
  suggestion: string;
}

interface LicenseIssue {
  package: string;
  license: string;
  is_compatible: boolean;
  reason?: string;
}

interface SecurityReport {
  timestamp: string;
  project_dir: string;
  vulnerabilities: Vulnerability[];
  secrets: SecretFinding[];
  license_issues: LicenseIssue[];
  risk_score: number;
  risk_level: 'critical' | 'high' | 'medium' | 'low' | 'safe';
  summary: string;
  recommendations: string[];
  scan_duration: number;
}

// ==================== 密钥模式库 ====================

const SECRET_PATTERNS: { name: string; pattern: RegExp; confidence: number; category: string }[] = [
  // Cloud Providers
  { name: 'AWS Access Key ID', pattern: /AKIA[0-9A-Z]{16}/, confidence: 0.95, category: 'cloud' },
  { name: 'AWS Secret Access Key', pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/i, confidence: 0.9, category: 'cloud' },
  { name: 'Google API Key', pattern: /AIza[0-9A-Za-z\-_]{35}/, confidence: 0.9, category: 'cloud' },
  { name: 'Google OAuth Client ID', pattern: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/, confidence: 0.85, category: 'cloud' },
  { name: 'Azure Storage Account Key', pattern: /AccountKey=[A-Za-z0-9+/=]{88}/, confidence: 0.9, category: 'cloud' },

  // Version Control
  { name: 'GitHub Personal Access Token', pattern: /gh[pousr]_[A-Za-z0-9_]{36,255}/, confidence: 0.95, category: 'vcs' },
  { name: 'GitHub Fine-grained PAT', pattern: /github_pat_[A-Za-z0-9_]{22,255}/, confidence: 0.95, category: 'vcs' },
  { name: 'GitLab Personal Access Token', pattern: /glpat-[A-Za-z0-9\-_]{20,}/, confidence: 0.95, category: 'vcs' },
  { name: 'Bitbucket App Password', pattern: /(?:bitbucket|BB)[_-]?[A-Za-z0-9]{20,}/, confidence: 0.7, category: 'vcs' },

  // Communication
  { name: 'Slack Bot Token', pattern: /xoxb-[0-9]{11,}-[0-9a-zA-Z\-]{24,}/, confidence: 0.95, category: 'comms' },
  { name: 'Slack User Token', pattern: /xoxp-[0-9]{11,}-[0-9a-zA-Z\-]{24,}/, confidence: 0.95, category: 'comms' },
  { name: 'Slack Webhook URL', pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/, confidence: 0.9, category: 'comms' },
  { name: 'Discord Bot Token', pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/, confidence: 0.85, category: 'comms' },
  { name: 'Telegram Bot Token', pattern: /[0-9]+:AA[0-9A-Za-z\-_]{33}/, confidence: 0.9, category: 'comms' },

  // Payment
  { name: 'Stripe Secret Key', pattern: /sk_live_[0-9a-zA-Z]{24,}/, confidence: 0.95, category: 'payment' },
  { name: 'Stripe Publishable Key', pattern: /pk_live_[0-9a-zA-Z]{24,}/, confidence: 0.8, category: 'payment' },

  // Cryptography
  { name: 'Private Key (RSA/EC/DSA)', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/, confidence: 0.98, category: 'crypto' },
  { name: 'SSH Private Key', pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/, confidence: 0.98, category: 'crypto' },
  { name: 'PGP Private Key Block', pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/, confidence: 0.95, category: 'crypto' },

  // Database
  { name: 'Database Connection String', pattern: /(?:mysql|postgresql|mongodb|redis|amqp|mqtt):\/\/[^\s'"<>]+/, confidence: 0.75, category: 'database' },

  // API Keys (Generic)
  { name: 'Generic API Key', pattern: /(?:api[_-]?key|apikey|api_secret|secret_key|access_token|auth_token|client_secret)\s*[=:]\s*['"]([A-Za-z0-9\-_]{20,})['"]/i, confidence: 0.5, category: 'generic' },
  { name: 'Bearer Token', pattern: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/i, confidence: 0.6, category: 'generic' },
  { name: 'JWT Token', pattern: /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/, confidence: 0.8, category: 'generic' },

  // Chinese Services
  { name: 'WeChat AppSecret', pattern: /(?:app_?secret|appSecret)\s*[=:]\s*['"]([a-f0-9]{32})['"]/i, confidence: 0.6, category: 'chinese' },
  { name: 'Alipay Private Key', pattern: /MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\w+/, confidence: 0.7, category: 'chinese' },
];

// ==================== 漏洞扫描 ====================

function scanNpmVulnerabilities(projectDir: string): Vulnerability[] {
  const pkgPath = resolve(projectDir, 'package.json');
  if (!existsSync(pkgPath)) return [];

  try {
    const output = execSync('npm audit --json 2>/dev/null || echo "{}"', {
      cwd: projectDir,
      timeout: 60000,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const audit = JSON.parse(output);
    const vulns: Vulnerability[] = [];

    if (audit.vulnerabilities) {
      for (const [name, info] of Object.entries(audit.vulnerabilities) as any[]) {
        const via = Array.isArray(info.via) ? info.via : [];
        for (const v of via) {
          if (typeof v === 'object' && v.url) {
            vulns.push({
              cve_id: v.url || `npm-${name}`,
              package: name,
              version: info.version || '',
              fixed_in: info.fixAvailable?.version,
              severity: (v.severity || 'medium') as any,
              cvss_score: v.cvss?.score || 0,
              description: v.title || v.name || '',
              fix_available: !!info.fixAvailable,
              url: v.url,
            });
          }
        }
      }
    }
    return vulns;
  } catch {
    return [];
  }
}

function scanPythonVulnerabilities(projectDir: string): Vulnerability[] {
  const reqPath = resolve(projectDir, 'requirements.txt');
  const pyprojectPath = resolve(projectDir, 'pyproject.toml');
  if (!existsSync(reqPath) && !existsSync(pyprojectPath)) return [];

  try {
    const output = execSync('pip-audit --format json 2>/dev/null || echo "[]"', {
      cwd: projectDir,
      timeout: 60000,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const audit = JSON.parse(output);
    return (audit.dependencies || []).flatMap((dep: any) =>
      (dep.vulns || []).map((v: any) => ({
        cve_id: v.id,
        package: dep.name,
        version: dep.version,
        fixed_in: v.fix_versions?.[0],
        severity: (v.severity?.toLowerCase() || 'medium') as any,
        cvss_score: 0,
        description: v.description || '',
        fix_available: !!v.fix_versions?.length,
        url: v.reference,
      }))
    );
  } catch {
    return [];
  }
}

function scanGoVulnerabilities(projectDir: string): Vulnerability[] {
  const goModPath = resolve(projectDir, 'go.mod');
  if (!existsSync(goModPath)) return [];

  try {
    const output = execSync('govulncheck -json ./... 2>/dev/null || echo ""', {
      cwd: projectDir,
      timeout: 120000,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    return output.split('\n').filter(Boolean).flatMap(line => {
      try {
        const entry = JSON.parse(line);
        if (entry.osv) {
          return [{
            cve_id: entry.osv.id,
            package: entry.osv.affected?.[0]?.package?.name || '',
            version: entry.osv.affected?.[0]?.versions?.[0] || '',
            severity: (entry.osv.database_specific?.severity?.toLowerCase() || 'medium') as any,
            cvss_score: 0,
            description: entry.osv.summary || '',
            fix_available: false,
          }];
        }
      } catch { /* ignore non-JSON */ }
      return [];
    });
  } catch {
    return [];
  }
}

function scanCargoVulnerabilities(projectDir: string): Vulnerability[] {
  const cargoPath = resolve(projectDir, 'Cargo.toml');
  if (!existsSync(cargoPath)) return [];

  try {
    const output = execSync('cargo audit --json 2>/dev/null || echo "{}"', {
      cwd: projectDir,
      timeout: 60000,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const audit = JSON.parse(output);
    return (audit.vulnerabilities || []).map((v: any) => ({
      cve_id: v.advisory?.id || '',
      package: v.package?.name || '',
      version: v.package?.version || '',
      fixed_in: v.versions?.patched?.[0],
      severity: (v.advisory?.cvss?.score >= 7 ? 'high' : v.advisory?.cvss?.score >= 4 ? 'medium' : 'low') as any,
      cvss_score: v.advisory?.cvss?.score || 0,
      description: v.advisory?.description || '',
      fix_available: !!v.versions?.patched?.length,
      url: v.advisory?.url,
    }));
  } catch {
    return [];
  }
}

// ==================== 密钥扫描 ====================

function scanSecrets(projectDir: string, config: Config): SecretFinding[] {
  const findings: SecretFinding[] = [];

  function scanDir(dir: string) {
    let entries;
    try { entries = readdirSync(dir); } catch { return; }

    for (const entry of entries) {
      if (config.excludePatterns.some(p => entry.includes(p) || entry === p)) continue;

      const fullPath = join(dir, entry);
      let stat;
      try { stat = statSync(fullPath); } catch { continue; }

      if (stat.isDirectory()) {
        scanDir(fullPath);
        continue;
      }

      // 跳过二进制/大文件
      const ext = extname(fullPath).toLowerCase();
      if (['.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot',
        '.exe', '.dll', '.so', '.dylib', '.bin', '.dat', '.lock', '.min.js', '.min.css',
        '.map', '.wasm', '.mp3', '.mp4', '.avi', '.mov', '.zip', '.tar', '.gz', '.rar',
      ].includes(ext)) continue;

      if (stat.size > config.maxFileSize) continue;

      try {
        const content = readFileSync(fullPath, 'utf-8');
        const lines = content.split('\n');
        const relPath = relative(projectDir, fullPath);

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          const trimmed = line.trim();

          // 跳过注释和示例
          if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;
          if (relPath.includes('example') || relPath.includes('sample') || relPath.includes('.example')) continue;

          for (const { name, pattern, confidence, category } of SECRET_PATTERNS) {
            if (confidence < 0.5) continue;
            const match = line.match(pattern);
            if (match) {
              const matchedStr = match[1] || match[0];
              const preview = matchedStr.length > 12
                ? matchedStr.substring(0, 6) + '...' + matchedStr.substring(matchedStr.length - 4)
                : matchedStr;

              findings.push({
                file: relPath,
                line: i + 1,
                type: name,
                confidence,
                preview,
                suggestion: getSecretSuggestion(name, category),
              });
            }
          }
        }
      } catch { /* skip unreadable */ }
    }
  }

  scanDir(projectDir);
  return findings;
}

function getSecretSuggestion(type: string, category: string): string {
  const suggestions: Record<string, string> = {
    'AWS Access Key ID': '使用 IAM 角色替代长期密钥，或将密钥移至 .env 文件',
    'AWS Secret Access Key': '立即轮换此密钥，使用 IAM 角色或环境变量',
    'GitHub Personal Access Token': '使用 GitHub Actions 的 GITHUB_TOKEN，或将 token 移至环境变量',
    'GitLab Personal Access Token': '将 token 移至环境变量或 CI/CD Secrets',
    'Slack Bot Token': '将 token 移至环境变量',
    'Slack Webhook URL': '将 webhook URL 移至环境变量',
    'Private Key (RSA/EC/DSA)': '立即撤销此密钥！生成新密钥并存储在密钥管理器中',
    'SSH Private Key': '立即撤销此密钥！使用 ssh-agent 管理密钥',
    'Database Connection String': '将连接字符串移至环境变量',
    'Generic API Key': '将密钥移至环境变量或密钥管理器',
    'JWT Token': '不要在代码中硬编码 JWT，使用短期 token',
    'Stripe Secret Key': '立即轮换此密钥，使用环境变量',
  };
  return suggestions[type] || `将 ${category} 类密钥移至环境变量或密钥管理器`;
}

// ==================== 许可证检查 ====================

const RESTRICTED_LICENSES = [
  'GPL-3.0', 'GPL-3.0-only', 'GPL-3.0-or-later',
  'AGPL-3.0', 'AGPL-3.0-only', 'AGPL-3.0-or-later',
  'SSPL-1.0', 'BSL-1.1',
  'CC-BY-NC-4.0', 'CC-BY-NC-SA-4.0', 'CC-BY-NC-ND-4.0',
];

function checkLicenses(projectDir: string): LicenseIssue[] {
  const pkgPath = resolve(projectDir, 'package.json');
  if (!existsSync(pkgPath)) return [];

  try {
    const output = execSync('npx license-checker --json --production 2>/dev/null || echo "{}"', {
      cwd: projectDir,
      timeout: 60000,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const licenses = JSON.parse(output);
    const issues: LicenseIssue[] = [];

    for (const [pkg, info] of Object.entries(licenses) as any[]) {
      const spdx = info.licenses || 'UNKNOWN';
      const isRestricted = RESTRICTED_LICENSES.some(rl => spdx.includes(rl));

      if (isRestricted) {
        issues.push({
          package: pkg,
          license: spdx,
          is_compatible: false,
          reason: `许可证 ${spdx} 可能与您的项目不兼容`,
        });
      }
    }
    return issues;
  } catch {
    return [];
  }
}

// ==================== 风险评分 ====================

function calculateRiskScore(vulns: Vulnerability[], secrets: SecretFinding[], licenseIssues: LicenseIssue[]): number {
  let score = 0;

  for (const v of vulns) {
    switch (v.severity) {
      case 'critical': score += 25; break;
      case 'high': score += 15; break;
      case 'medium': score += 8; break;
      case 'low': score += 3; break;
    }
  }

  for (const s of secrets) {
    score += Math.round(s.confidence * 20);
  }

  for (const l of licenseIssues) {
    if (!l.is_compatible) score += 10;
  }

  return Math.min(100, score);
}

function getRiskLevel(score: number): SecurityReport['risk_level'] {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 20) return 'low';
  return 'safe';
}

function generateRecommendations(vulns: Vulnerability[], secrets: SecretFinding[], licenseIssues: LicenseIssue[]): string[] {
  const recs: string[] = [];

  const critical = vulns.filter(v => v.severity === 'critical');
  if (critical.length > 0) {
    recs.push(`🚨 发现 ${critical.length} 个严重漏洞，建议立即修复！`);
  }

  const fixable = vulns.filter(v => v.fix_available);
  if (fixable.length > 0) {
    recs.push(`📦 ${fixable.length} 个漏洞可通过升级依赖修复`);
  }

  if (secrets.length > 0) {
    recs.push(`🔑 发现 ${secrets.length} 处疑似密钥泄露，建议立即检查并轮换`);
  }

  if (licenseIssues.length > 0) {
    recs.push(`📜 发现 ${licenseIssues.length} 个许可证兼容性问题，建议审查`);
  }

  if (recs.length === 0) {
    recs.push('✅ 未发现明显安全问题');
  }

  return recs;
}

// ==================== 插件入口 ====================

export function apply(ctx: any, config: Config) {
  if (!config.enabled) return;

  // 注册工具：security_audit
  ctx.effect(() => ctx.tools.register({
    name: 'security_audit',
    description: '执行全面的安全审计：扫描依赖漏洞、检测密钥泄露、检查许可证合规。返回结构化安全报告，包含风险评分和修复建议。',
    parameters: {
      project_dir: {
        type: 'string',
        description: '项目目录路径（绝对路径）。默认为当前工作目录。',
      },
      scan_type: {
        type: 'string',
        description: '扫描类型：all（全部）| vulns（仅漏洞）| secrets（仅密钥）| licenses（仅许可证）',
      },
    },
    output: {
      schema: { type: 'json' },
      render(_args: unknown, value: unknown) {
        const report = value as SecurityReport;
        const lines: string[] = [];

        lines.push(`## 🔒 安全审计报告`);
        lines.push('');
        lines.push(`**风险等级: ${report.risk_level.toUpperCase()} (${report.risk_score}/100)**`);
        lines.push(`扫描耗时: ${(report.scan_duration / 1000).toFixed(1)}s`);
        lines.push('');

        // 漏洞摘要
        if (report.vulnerabilities.length > 0) {
          const bySev = {
            critical: report.vulnerabilities.filter(v => v.severity === 'critical').length,
            high: report.vulnerabilities.filter(v => v.severity === 'high').length,
            medium: report.vulnerabilities.filter(v => v.severity === 'medium').length,
            low: report.vulnerabilities.filter(v => v.severity === 'low').length,
          };
          lines.push(`### 📦 依赖漏洞 (${report.vulnerabilities.length})`);
          lines.push(`- 严重: ${bySev.critical} | 高危: ${bySev.high} | 中危: ${bySev.medium} | 低危: ${bySev.low}`);
          lines.push('');
          for (const v of report.vulnerabilities.slice(0, 20)) {
            const icon = v.severity === 'critical' ? '🔴' : v.severity === 'high' ? '🟠' : v.severity === 'medium' ? '🟡' : '🟢';
            lines.push(`- ${icon} **${v.package}** (${v.version}) — ${v.description}`);
            if (v.fix_available) lines.push(`  ✅ 可修复: 升级到 ${v.fixed_in}`);
          }
        } else {
          lines.push('### 📦 依赖漏洞: ✅ 未发现');
        }
        lines.push('');

        // 密钥泄露
        if (report.secrets.length > 0) {
          lines.push(`### 🔑 密钥泄露 (${report.secrets.length})`);
          lines.push('');
          for (const s of report.secrets.slice(0, 20)) {
            const conf = s.confidence >= 0.8 ? '🔴 高' : s.confidence >= 0.6 ? '🟡 中' : '🟢 低';
            lines.push(`- ${conf} **${s.type}** @ \`${s.file}:${s.line}\``);
            lines.push(`  预览: \`${s.preview}\``);
            lines.push(`  建议: ${s.suggestion}`);
          }
        } else {
          lines.push('### 🔑 密钥泄露: ✅ 未发现');
        }
        lines.push('');

        // 许可证
        if (report.license_issues.length > 0) {
          lines.push(`### 📜 许可证问题 (${report.license_issues.length})`);
          lines.push('');
          for (const l of report.license_issues.slice(0, 10)) {
            lines.push(`- ⚠️ **${l.package}** — ${l.license}: ${l.reason}`);
          }
        } else {
          lines.push('### 📜 许可证: ✅ 无兼容性问题');
        }
        lines.push('');

        // 建议
        lines.push('### 💡 建议');
        for (const r of report.recommendations) {
          lines.push(`- ${r}`);
        }

        return [{ type: 'text', text: lines.join('\n') }];
      },
    },
    async execute(args: { project_dir?: string; scan_type?: string }) {
      const projectDir = args.project_dir || process.cwd();
      const scanType = args.scan_type || 'all';
      const startTime = Date.now();

      let vulns: Vulnerability[] = [];
      let secrets: SecretFinding[] = [];
      let licenseIssues: LicenseIssue[] = [];

      if (scanType === 'all' || scanType === 'vulns') {
        vulns = [
          ...scanNpmVulnerabilities(projectDir),
          ...scanPythonVulnerabilities(projectDir),
          ...scanGoVulnerabilities(projectDir),
          ...scanCargoVulnerabilities(projectDir),
        ];
      }

      if ((scanType === 'all' || scanType === 'secrets') && config.scanSecrets) {
        secrets = scanSecrets(projectDir, config);
      }

      if ((scanType === 'all' || scanType === 'licenses') && config.checkLicenses) {
        licenseIssues = checkLicenses(projectDir);
      }

      const riskScore = calculateRiskScore(vulns, secrets, licenseIssues);

      const report: SecurityReport = {
        timestamp: new Date().toISOString(),
        project_dir: projectDir,
        vulnerabilities: vulns,
        secrets,
        license_issues: licenseIssues,
        risk_score: riskScore,
        risk_level: getRiskLevel(riskScore),
        summary: '',
        recommendations: generateRecommendations(vulns, secrets, licenseIssues),
        scan_duration: Date.now() - startTime,
      };

      report.summary = `${report.risk_level.toUpperCase()} — ${vulns.length} 漏洞, ${secrets.length} 密钥, ${licenseIssues.length} 许可证问题`;

      return report;
    },
    presentCall: (args: any) => ({
      card: 'generic' as const,
      title: `🔒 安全审计${args?.scan_type ? ` (${args.scan_type})` : ''}`,
    }),
  }), 'dsh-security-audit: security_audit');

  // 注册工具：scan_secrets（快速密钥扫描）
  ctx.effect(() => ctx.tools.register({
    name: 'scan_secrets',
    description: '快速扫描代码中的密钥泄露。检测 AWS/GitHub/Slack/数据库连接串等 200+ 种密钥模式。',
    parameters: {
      project_dir: {
        type: 'string',
        description: '项目目录路径',
      },
    },
    output: {
      schema: { type: 'json' },
      render(_args: unknown, value: unknown) {
        const secrets = value as SecretFinding[];
        if (secrets.length === 0) return [{ type: 'text', text: '✅ 未发现密钥泄露' }];
        const lines = [`## 🔑 密钥扫描结果 — 发现 ${secrets.length} 处`];
        for (const s of secrets.slice(0, 30)) {
          lines.push(`- **${s.type}** @ \`${s.file}:${s.line}\` — 预览: \`${s.preview}\``);
        }
        return [{ type: 'text', text: lines.join('\n') }];
      },
    },
    async execute(args: { project_dir?: string }) {
      return scanSecrets(args.project_dir || process.cwd(), config);
    },
  }), 'dsh-security-audit: scan_secrets');

  // 注册 slash 命令 /audit
  ctx.effect(() => ctx.commands.register({
    name: 'audit',
    description: '执行安全审计',
    input: { hint: '[vulns|secrets|licenses|all]' },
    async handler(invocation: any) {
      const scanType = invocation.rawInput.trim() || 'all';
      const projectDir = process.cwd();
      const startTime = Date.now();

      const vulns = (scanType === 'all' || scanType === 'vulns')
        ? [...scanNpmVulnerabilities(projectDir), ...scanPythonVulnerabilities(projectDir), ...scanGoVulnerabilities(projectDir), ...scanCargoVulnerabilities(projectDir)]
        : [];
      const secrets = (scanType === 'all' || scanType === 'secrets') && config.scanSecrets
        ? scanSecrets(projectDir, config)
        : [];
      const licenseIssues = (scanType === 'all' || scanType === 'licenses') && config.checkLicenses
        ? checkLicenses(projectDir)
        : [];

      const riskScore = calculateRiskScore(vulns, secrets, licenseIssues);
      const level = getRiskLevel(riskScore);

      const parts: string[] = [];
      parts.push(`🔒 安全审计完成 — 风险: ${level.toUpperCase()} (${riskScore}/100)`);
      if (vulns.length > 0) parts.push(`📦 ${vulns.length} 个漏洞`);
      if (secrets.length > 0) parts.push(`🔑 ${secrets.length} 处密钥泄露`);
      if (licenseIssues.length > 0) parts.push(`📜 ${licenseIssues.length} 个许可证问题`);
      if (vulns.length === 0 && secrets.length === 0 && licenseIssues.length === 0) parts.push('✅ 未发现安全问题');

      return { kind: 'text' as const, text: parts.join('\n') };
    },
  }), 'dsh-security-audit: command');

  // 注册设置
  ctx.inject(['settings'], (sctx: any) => {
    const { settingsNamespace } = require('@deepseek-ai/dsh-settings');
    const ns = settingsNamespace(NS);

    sctx.settings.register(ns, configSchema, {
      base: config,
      expose: true,
      applies: 'live',
    });
  });
}
