/**
 * Offline secret and risky-pattern scanner plus a heuristic dependency audit.
 * `scan_secrets` runs regex signatures over a caller-supplied map of file
 * contents (it never touches the filesystem); `audit_package` inspects a
 * package.json body for packages with recorded supply-chain incidents,
 * look-alike names, volatile dependency sources, and install-time code hooks.
 * Everything is pure pattern matching: no advisory fetch, no network, no
 * subprocess, no filesystem read.
 * @module @qingshanjiluo/dsh-security-audit
 */

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import z from '@deepseek-ai/schemastery'

export const name = 'dsh-security-audit'
export const inject = ['tools']

/** Deployment policy for the security auditor. */
export interface Config {
  /**
   * Per-file UTF-8 ceiling the deployment enforces. A caller may ask for a
   * smaller `maxBytes`, and `0` means "use this ceiling"; nothing larger is
   * pattern-matched, it is skipped and reported instead.
   */
  maxBytes: number
  /** Upper bound on findings returned by one call; the rest are counted only. */
  maxFindings: number
  /** Signature ids this deployment wants switched off (for example `eval`). */
  disabledRules: string[]
  /** Deployment blocklist: exact names, scope prefixes, or substrings. */
  extraRiskyPackages: string[]
  /** Whether `audit_package` flags risky packages found under devDependencies by default. A call may override per-request. */
  includeDevDependencies: boolean
}

/** Schemastery configuration for the security auditor. */
export const Config: z<Config> = z.object({
  maxBytes: z.number().default(262144),
  maxFindings: z.number().default(200),
  disabledRules: z.array(z.string()).default([]),
  extraRiskyPackages: z.array(z.string()).default([]),
  includeDevDependencies: z.boolean().default(false),
})

type Severity = 'high' | 'medium' | 'low'
type RuleKind = 'secret' | 'risky-pattern'

/** One line-level signature applied by `scan_secrets`. */
interface Signature {
  readonly rule: string
  readonly kind: RuleKind
  readonly severity: Severity
  readonly pattern: RegExp
  readonly message: string
  /** True when the matched text is itself credential material. */
  readonly sensitive: boolean
}

interface ScanFinding {
  rule: string
  kind: RuleKind
  severity: Severity
  path: string
  line: number
  evidence: string
  message: string
}

interface SkippedFile {
  path: string
  reason: string
}

/** Credential signatures. Every pattern is global and used via `matchAll`. */
const SECRET_SIGNATURES: readonly Signature[] = [
  {
    rule: 'aws-access-key-id',
    kind: 'secret',
    severity: 'high',
    sensitive: true,
    pattern: /\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|ANPA|ANVA|AROA)[0-9A-Z]{16}\b/g,
    message: 'AWS access key ID. Rotate the key and keep credentials out of tracked files.',
  },
  {
    rule: 'aws-secret-access-key',
    kind: 'secret',
    severity: 'high',
    sensitive: true,
    pattern: /\baws[_-]?secret[_-]?access[_-]?key\b[\s:=,]+["']?[A-Za-z0-9/+=]{40}\b/gi,
    message: 'AWS secret access key assignment. Rotate it and load it from the environment.',
  },
  {
    rule: 'private-key-block',
    kind: 'secret',
    severity: 'high',
    sensitive: false,
    pattern: /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
    message: 'Private key material. Never commit keys; move them into a secret store.',
  },
  {
    rule: 'github-token',
    kind: 'secret',
    severity: 'high',
    sensitive: true,
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b/g,
    message: 'GitHub token (classic or fine-grained). Revoke it and re-issue with least scope.',
  },
  {
    rule: 'gitlab-token',
    kind: 'secret',
    severity: 'high',
    sensitive: true,
    pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
    message: 'GitLab personal or project access token. Revoke it.',
  },
  {
    rule: 'slack-token',
    kind: 'secret',
    severity: 'high',
    sensitive: true,
    pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
    message: 'Slack API token. Revoke it in the Slack app settings.',
  },
  {
    rule: 'stripe-key',
    kind: 'secret',
    severity: 'high',
    sensitive: true,
    pattern: /\b[spr]k_live_[0-9a-zA-Z]{20,}\b/g,
    message: 'Live Stripe secret key. Rotate it immediately.',
  },
  {
    rule: 'google-api-key',
    kind: 'secret',
    severity: 'high',
    sensitive: true,
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    message: 'Google API key. Restrict or rotate it in the Cloud console.',
  },
  {
    rule: 'npm-token',
    kind: 'secret',
    severity: 'high',
    sensitive: true,
    pattern: /\bnpm_[A-Za-z0-9]{30,}\b/g,
    message: 'npm access token. Revoke it on the registry.',
  },
  {
    rule: 'pypi-token',
    kind: 'secret',
    severity: 'high',
    sensitive: true,
    pattern: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{40,}\b/g,
    message: 'PyPI upload token. Revoke it; prefer trusted publishing.',
  },
  {
    rule: 'sendgrid-key',
    kind: 'secret',
    severity: 'high',
    sensitive: true,
    pattern: /\bSG\.[A-Za-z0-9_-]{20,40}\.[A-Za-z0-9_-]{20,60}\b/g,
    message: 'SendGrid API key. Rotate it.',
  },
  {
    rule: 'twilio-credential',
    kind: 'secret',
    severity: 'high',
    sensitive: true,
    pattern: /\bAC[0-9a-fA-F]{32}\b/g,
    message: 'Twilio credential. Rotate it.',
  },
  {
    rule: 'llm-provider-key',
    kind: 'secret',
    severity: 'high',
    sensitive: true,
    pattern: /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b/g,
    message: 'LLM provider API key shape. Rotate it and read it from the environment.',
  },
  {
    rule: 'jwt',
    kind: 'secret',
    severity: 'medium',
    sensitive: true,
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    message: 'JSON Web Token embedded in source. Treat it as a bearer credential.',
  },
  {
    rule: 'credential-in-url',
    kind: 'secret',
    severity: 'medium',
    sensitive: true,
    pattern: /\b[a-z][a-z0-9+.-]{1,12}:\/\/[^/\s:@]+:[^/\s@]{3,}@[a-z0-9.-]+/gi,
    message: 'Inline user:password in a URL. Move credentials into configuration.',
  },
  {
    rule: 'generic-secret-assignment',
    kind: 'secret',
    severity: 'medium',
    sensitive: true,
    pattern: /(?:^|[^\w])(?:[a-z0-9]*[_-])?(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|password|passwd|pwd|token|secret)["']?\s*[:=]\s*["'][^"'\s]{8,}["']/gi,
    message: 'Hardcoded secret-looking assignment. Load the value from the environment instead.',
  },
  {
    rule: 'env-style-secret',
    kind: 'secret',
    severity: 'medium',
    sensitive: true,
    pattern: /(?:^|[\s;])(?:export\s+)?[a-z0-9_]*(?:secret|token|password|passwd|api[_-]?key|access[_-]?key|credential|private[_-]?key)[a-z0-9_]*=(?:[^\s"']{16,}|[^\s"']*[0-9][^\s"']{4,})/gi,
    message: 'Assignment whose name and value both look like a credential. Keep it out of tracked files.',
  },
]

/** Code shapes that routinely turn into vulnerabilities. */
const PATTERN_SIGNATURES: readonly Signature[] = [
  {
    rule: 'interpolated-shell-command',
    kind: 'risky-pattern',
    severity: 'high',
    sensitive: false,
    pattern: /\b(?:exec|execSync|spawn|spawnSync|execFile)\s*\(\s*(?:[`"'][^`"']*\$\{|[`"'][^`"']*["']\s*\+)/g,
    message: 'Shell command assembled from interpolation. Pass an argv array instead of a string.',
  },
  {
    rule: 'python-shell-true',
    kind: 'risky-pattern',
    severity: 'high',
    sensitive: false,
    pattern: /\bsubprocess\.[a-z_]+\([^)]*\bshell\s*=\s*True\b/gi,
    message: 'subprocess call with shell=True. Pass an argv list instead.',
  },
  {
    rule: 'os-system',
    kind: 'risky-pattern',
    severity: 'medium',
    sensitive: false,
    pattern: /\bos\.system\s*\(/g,
    message: 'os.system() runs through a shell. Prefer subprocess with an argv list.',
  },
  {
    rule: 'unsafe-deserialization',
    kind: 'risky-pattern',
    severity: 'high',
    sensitive: false,
    pattern: /\b(?:pickle\.loads?\s*\(|torch\.load\s*\(|yaml\.load\s*\((?![^)]*SafeLoader)|unserialize\s*\()/g,
    message: 'Unsafe deserialization entry point — attacker-controlled bytes reach an object graph.',
  },
  {
    rule: 'html-injection-sink',
    kind: 'risky-pattern',
    severity: 'medium',
    sensitive: false,
    pattern: /\b(?:dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\(|v-html=|\{\{\{)/g,
    message: 'Raw HTML sink. Sanitize before rendering untrusted markup.',
  },
  {
    rule: 'sql-string-concat',
    kind: 'risky-pattern',
    severity: 'high',
    sensitive: false,
    pattern: /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^\n;]*["'`]\s*\+|\b(?:execute|query)\s*\(\s*[`"'][^`"']*\$\{/gi,
    message: 'SQL built by string concatenation. Use parameterised statements.',
  },
  {
    rule: 'disabled-tls-verification',
    kind: 'risky-pattern',
    severity: 'high',
    sensitive: false,
    pattern: /\b(?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|ssl\s*=\s*False|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER[^\n]{0,8}(?:0|false|FALSE))/g,
    message: 'TLS verification disabled. Any certificate becomes acceptable.',
  },
  {
    rule: 'dynamic-code-eval',
    kind: 'risky-pattern',
    severity: 'medium',
    sensitive: false,
    pattern: /\b(?:eval\s*\(|new\s+Function\s*\()/g,
    message: 'Dynamic code evaluation. If the input is remote, this is remote code execution.',
  },
  {
    rule: 'path-traversal-prone',
    kind: 'risky-pattern',
    severity: 'medium',
    sensitive: false,
    pattern: /\b(?:readFile|readFileSync|createReadStream|sendfile|send_file|path\.join)\s*\(\s*[^)]*(?:req\.|params\.|query\.|\$\{|\+\s*\w)/g,
    message: 'File path assembled from request data. Canonicalise it and confine it to a root.',
  },
  {
    rule: 'weak-hash-for-secret',
    kind: 'risky-pattern',
    severity: 'low',
    sensitive: false,
    pattern: /\b(?:md5|sha1)\s*\(\s*[^)]*(?:password|passwd|secret|token)/gi,
    message: 'Fast hash over secret material. Use bcrypt, scrypt, or argon2 for passwords.',
  },
]

const ALL_SIGNATURES: readonly Signature[] = [...SECRET_SIGNATURES, ...PATTERN_SIGNATURES]

const SEVERITY_ORDER: Record<Severity, number> = { high: 0, medium: 1, low: 2 }

const MAX_EVIDENCE = 160

/**
 * Mask a match so a finding proves the shape without re-publishing the value.
 * @param text - raw matched text.
 * @returns masked text that keeps a short prefix and suffix.
 */
function redact(text: string): string {
  const chars = [...text]
  if (chars.length <= 12) return `${chars.slice(0, 2).join('')}${'*'.repeat(Math.max(1, chars.length - 2))}`
  const head = chars.slice(0, 6).join('')
  const tail = chars.slice(-3).join('')
  return `${head}${'*'.repeat(Math.min(24, chars.length - 9))}${tail}`
}

/**
 * Fit a line or script body into the evidence budget.
 * @param text - candidate evidence string.
 * @returns whitespace-collapsed text, elided in the middle when too long.
 */
function clip(text: string): string {
  const flat = text.replace(/\s+/g, ' ').trim()
  if (flat.length <= MAX_EVIDENCE) return flat
  const head = flat.slice(0, Math.floor(MAX_EVIDENCE / 2))
  const tail = flat.slice(-Math.floor(MAX_EVIDENCE / 4))
  return `${head} … ${tail}`
}

/**
 * Deterministic report order: path, then line, then severity, then rule.
 * @param a - first finding.
 * @param b - second finding.
 * @returns negative, zero, or positive ordering number.
 */
function orderScanFindings(a: ScanFinding, b: ScanFinding): number {
  if (a.path !== b.path) return a.path < b.path ? -1 : 1
  if (a.line !== b.line) return a.line - b.line
  if (a.severity !== b.severity) return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  return a.rule < b.rule ? -1 : a.rule > b.rule ? 1 : 0
}

/**
 * Run every active signature over one file's contents.
 * @param path - caller-supplied path echoed into findings.
 * @param content - full text of the file.
 * @param signatures - signatures to apply.
 * @returns findings in line order, deduplicated per line and rule.
 */
function scanContent(path: string, content: string, signatures: readonly Signature[]): ScanFinding[] {
  const found: ScanFinding[] = []
  const seen = new Set<string>()
  const lines = content.split(/\r?\n/)
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index] ?? ''
    if (line.length === 0) continue
    for (const signature of signatures) {
      for (const match of line.matchAll(signature.pattern)) {
        const raw = match[0] ?? ''
        if (raw.length === 0) continue
        const key = `${index}|${signature.rule}|${raw}`
        if (seen.has(key)) continue
        seen.add(key)
        found.push({
          rule: signature.rule,
          kind: signature.kind,
          severity: signature.severity,
          path,
          line: index + 1,
          evidence: signature.sensitive ? clip(redact(raw)) : clip(raw),
          message: signature.message,
        })
      }
    }
  }
  return found
}

/**
 * Scan a caller-supplied content map. Pure — it reads no filesystem state.
 * @param files - map of path to file content.
 * @param maxBytes - per-file UTF-8 budget; zero or less means unlimited.
 * @param maxFindings - report cap; `0` or less means uncapped.
 * @param disabled - signature rule ids this deployment switched off.
 * @returns sorted findings, severity counts, and skipped files.
 */
function scanFiles(
  files: Record<string, unknown>,
  maxBytes: number,
  maxFindings: number,
  disabled: ReadonlySet<string>,
): { scanned: number; counts: { high: number; medium: number; low: number }; truncated: boolean; findings: ScanFinding[]; skipped: SkippedFile[] } {
  const counts = { high: 0, medium: 0, low: 0 }
  const skipped: SkippedFile[] = []
  const collected: ScanFinding[] = []
  const active = disabled.size === 0 ? ALL_SIGNATURES : ALL_SIGNATURES.filter(s => !disabled.has(s.rule))
  let scanned = 0
  for (const path of Object.keys(files).sort()) {
    const value = files[path]
    if (typeof value !== 'string') {
      skipped.push({ path, reason: 'content is not a string' })
      continue
    }
    if (value.includes('\u0000')) {
      skipped.push({ path, reason: 'binary content' })
      continue
    }
    if (maxBytes > 0) {
      const size = Buffer.byteLength(value, 'utf8')
      if (size > maxBytes) {
        skipped.push({ path, reason: `${size} bytes exceeds the ${maxBytes} byte budget` })
        continue
      }
    }
    scanned += 1
    for (const finding of scanContent(path, value, active)) {
      counts[finding.severity] += 1
      collected.push(finding)
    }
  }
  collected.sort(orderScanFindings)
  const cap = maxFindings > 0 ? maxFindings : Number.POSITIVE_INFINITY
  const kept = collected.slice(0, cap)
  return {
    scanned,
    counts,
    truncated: kept.length < collected.length,
    findings: kept,
    skipped,
  }
}

/** Package names with a recorded supply-chain incident. */
const KNOWN_RISKY: Readonly<Record<string, { severity: Severity; note: string }>> = {
  'event-stream': { severity: 'high', note: '3.3.x was hijacked to ship a cryptocurrency-theft payload; replace it or pin >= 4.0.0.' },
  'flatmap-stream': { severity: 'high', note: 'the payload injected by the event-stream incident; it has no legitimate use.' },
  'ua-parser-js': { severity: 'medium', note: '0.7.29 and 1.0.0 were published from a compromised account carrying a cryptominer.' },
  'coa': { severity: 'medium', note: '2.0.3 and 1.0.5 were hijacked to install a miner.' },
  'cryptr': { severity: 'medium', note: 'listed in the 2021 dependency-confusion advisory set.' },
  'node-df': { severity: 'medium', note: 'listed in the 2021 dependency-confusion advisory set.' },
  'node-ipc': { severity: 'medium', note: 'protestware releases ran on the host machine at install time.' },
  'peacenotwar': { severity: 'medium', note: 'protestware companion pulled in by node-ipc.' },
  'colors': { severity: 'low', note: 'intentionally broken maintainer releases — treat as an availability risk.' },
  'faker': { severity: 'low', note: 'intentionally broken maintainer releases — treat as an availability risk.' },
}

/** Popular names used as the reference set for look-alike detection. */
const POPULAR_NAMES: readonly string[] = [
  'react', 'lodash', 'express', 'axios', 'moment', 'commander', 'chalk', 'debug', 'request',
  'webpack', 'eslint', 'prettier', 'typescript', 'jest', 'vue', 'angular', 'next', 'dotenv',
  'node-fetch', 'undici', 'got', 'semver', 'minimist', 'yargs', 'inquirer', 'glob', 'rimraf',
  'mkdirp', 'nanoid', 'uuid', 'zod', 'dayjs', 'ramda', 'cors', 'body-parser', 'mongoose',
  'passport', 'jsonwebtoken', 'nodemon', 'tailwindcss', 'immutable', 'socket.io', 'ws',
]

const DEPENDENCY_SECTIONS: readonly string[] = [
  'dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies',
]

const OVERRIDE_SECTIONS: readonly string[] = ['resolutions', 'overrides']

const COUNTED_SECTIONS: readonly string[] = ['dependencies', 'devDependencies', 'optionalDependencies']

/** Lifecycle hooks that execute arbitrary code on install. */
const INSTALL_HOOKS: readonly string[] = ['preinstall', 'install', 'postinstall', 'prepare']

const RISKY_SCRIPT_SIGNATURES: readonly { rule: string; pattern: RegExp; message: string }[] = [
  {
    rule: 'curl-piped-to-shell',
    pattern: /\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b/,
    message: 'pipes a remote script straight into a shell',
  },
  {
    rule: 'decoded-blob-execution',
    pattern: /\bbase64\b[^\n]*\||\bfromCharCode\b|\batob\s*\(/i,
    message: 'decodes an opaque blob before running it — a classic obfuscation channel',
  },
  {
    rule: 'reverse-shell-shape',
    pattern: /\/dev\/tcp\/|\bnc(?:\.exe)?\s+-[a-z]*e\b|\bncat\b[^\n]*--sh-exec/i,
    message: 'opens a reverse shell from a lifecycle script',
  },
  {
    rule: 'encoded-powershell',
    pattern: /\bpowershell(?:\.exe)?\b[^\n]*-(?:e|enc|ep)\b|\bcmd(?:\.exe)?\s+\/c\s+echo/i,
    message: 'runs an encoded command through a Windows shell',
  },
  {
    rule: 'network-fetch-at-install',
    pattern: /\b(?:curl|wget)\b|\bnode\s+(?:-e|--eval)\b|https?:\/\/[a-z0-9.-]+\.(?:onion|xyz|top|tk)\b/i,
    message: 'reaches the network during install, usually to fetch a binary payload',
  },
]

/**
 * Bounded Damerau-style edit distance for short package names.
 * @param a - first name.
 * @param b - second name.
 * @returns edit distance capped at three (anything further reads as `3`).
 */
function editDistance(a: string, b: string): number {
  if (a === b) return 0
  const left = [...a]
  const right = [...b]
  if (Math.abs(left.length - right.length) > 2) return 3
  const columns = right.length + 1
  const table = new Array<number>((left.length + 1) * columns)
  for (let i = 0; i <= left.length; i++) table[i * columns] = i
  for (let j = 0; j < columns; j++) table[j] = j
  for (let i = 1; i <= left.length; i++) {
    for (let j = 1; j <= right.length; j++) {
      const cost = left[i - 1] === right[j - 1] ? 0 : 1
      const substitute = table[(i - 1) * columns + j - 1] ?? 0
      const deleteCell = table[(i - 1) * columns + j] ?? 0
      const insertCell = table[i * columns + j - 1] ?? 0
      let best = Math.min(substitute + cost, deleteCell + 1, insertCell + 1)
      if (i > 1 && j > 1 && left[i - 1] === right[j - 2] && left[i - 2] === right[j - 1]) {
        best = Math.min(best, (table[(i - 2) * columns + j - 2] ?? 0) + 1)
      }
      table[i * columns + j] = best
    }
  }
  return table[left.length * columns + right.length] ?? 3
}

interface AuditFinding {
  rule: string
  severity: Severity
  pkg: string
  range: string
  message: string
}

/**
 * Classify one dependency entry against the offline heuristics.
 * @param pkg - dependency name as written.
 * @param range - declared version range.
 * @param section - where it was declared, for the message.
 * @param blocklist - deployment-blocklisted names.
 * @returns findings for this entry.
 */
function classifyDependency(pkg: string, range: string, section: string, blocklist: readonly string[]): AuditFinding[] {
  const findings: AuditFinding[] = []
  const bare = pkg.startsWith('@') ? pkg.slice(pkg.indexOf('/') + 1) : pkg
  const known = KNOWN_RISKY[bare] ?? KNOWN_RISKY[pkg]
  if (known) {
    findings.push({ rule: 'known-risky-package', severity: known.severity, pkg, range, message: `${pkg} (${section}): ${known.note}` })
  } else if (bare.length >= 4 && !POPULAR_NAMES.includes(bare)) {
    for (const popular of POPULAR_NAMES) {
      const budget = bare.length >= 8 ? 2 : 1
      const distance = editDistance(bare, popular)
      if (distance >= 1 && distance <= budget) {
        findings.push({
          rule: 'possible-typosquat',
          severity: 'medium',
          pkg,
          range,
          message: `${pkg} (${section}) is ${distance === 1 ? 'one edit' : 'two edits'} away from the popular package "${popular}". Confirm the name before installing.`,
        })
        break
      }
    }
  }
  const needle = pkg.toLowerCase()
  for (const blocked of blocklist) {
    const key = blocked.toLowerCase()
    if (key.length > 0 && (needle === key || needle.startsWith(`${key}/`) || needle.includes(key))) {
      findings.push({ rule: 'blocklisted-package', severity: 'high', pkg, range, message: `${pkg} (${section}) matches the deployment blocklist entry "${blocked}".` })
      break
    }
  }
  const trimmed = range.trim()
  if (/^http:\/\//i.test(trimmed)) {
    findings.push({ rule: 'insecure-dependency-url', severity: 'high', pkg, range, message: `${pkg} (${section}) is fetched over plaintext HTTP; the tarball can be swapped in transit.` })
  } else if (/^(?:git\+|git:|github:)/i.test(trimmed) || /^[\w.-]+\/[\w.+-]+/.test(trimmed) || /\.git(?:$|[#/])/i.test(trimmed)) {
    const pinned = /#[0-9a-f]{7,40}$|#refs\/tags\//i.test(trimmed)
    findings.push({
      rule: 'git-dependency',
      severity: pinned ? 'low' : 'medium',
      pkg,
      range,
      message: pinned
        ? `${pkg} (${section}) installs from git at a pinned commit; the download bypasses registry integrity checks.`
        : `${pkg} (${section}) installs from a mutable git reference — anyone who can push there runs code in your build.`,
    })
  } else if (/^file:/.test(trimmed)) {
    findings.push({ rule: 'local-path-dependency', severity: 'low', pkg, range, message: `${pkg} (${section}) resolves to a local path; CI and other clones may resolve something different.` })
  }
  if (trimmed.length === 0 || trimmed === '*' || trimmed.toLowerCase() === 'latest') {
    findings.push({ rule: 'unpinned-range', severity: 'medium', pkg, range, message: `${pkg} (${section}) has no version constraint; every install can pull a different build.` })
  }
  return findings
}

/** One flattened dependency declaration from a manifest section. */
interface DependencyEntry {
  name: string
  display: string
  range: string
}

/**
 * Flatten a manifest section into name/range pairs, one nesting level deep so
 * `overrides` blocks such as `{ "a": { "b": "^1.0.0" } }` still get inspected.
 * @param block - the raw section value.
 * @returns entries in name order.
 */
function flattenSection(block: unknown): DependencyEntry[] {
  if (typeof block !== 'object' || block === null) return []
  const entries: DependencyEntry[] = []
  for (const [name, value] of Object.entries(block as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    if (typeof value === 'string') {
      entries.push({ name, display: name, range: value })
      continue
    }
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      entries.push({ name, display: name, range: Array.isArray(value) ? `[${value.join(', ')}]` : String(value ?? '') })
      continue
    }
    for (const [inner, innerValue] of Object.entries(value as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
      entries.push({
        name: inner,
        display: `${name} > ${inner}`,
        range: typeof innerValue === 'string' ? innerValue : String(innerValue ?? ''),
      })
    }
  }
  return entries
}

/**
 * Audit a package.json body with offline heuristics. Pure and deterministic.
 * @param text - raw package.json contents.
 * @param includeDev - whether devDependencies are audited.
 * @param blocklist - deployment-added risky names.
 * @returns parsed metadata plus every heuristic hit, most severe first.
 */
function auditPackage(text: string, includeDev: boolean, blocklist: readonly string[]): {
  ok: boolean
  error: string
  pkg: string
  dependencyCount: number
  counts: { high: number; medium: number; low: number }
  findings: AuditFinding[]
} {
  const counts = { high: 0, medium: 0, low: 0 }
  const findings: AuditFinding[] = []
  const push = (finding: AuditFinding): void => {
    counts[finding.severity] += 1
    findings.push(finding)
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(text.replace(/^\uFEFF/, ''))
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error), pkg: '', dependencyCount: 0, counts, findings }
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { ok: false, error: 'package.json must contain a JSON object', pkg: '', dependencyCount: 0, counts, findings }
  }
  const manifest = parsed as Record<string, unknown>
  const pkgName = typeof manifest['name'] === 'string' ? manifest['name'] : ''
  let dependencyCount = 0

  for (const section of [...DEPENDENCY_SECTIONS, ...OVERRIDE_SECTIONS]) {
    if (section === 'devDependencies' && !includeDev) continue
    const block = manifest[section]
    if (block === undefined) continue
    if (typeof block !== 'object' || block === null || Array.isArray(block)) {
      push({ rule: 'malformed-section', severity: 'low', pkg: pkgName || '(unnamed)', range: '', message: `"${section}" is not an object, so its entries were not audited.` })
      continue
    }
    const entries = flattenSection(block)
    if (COUNTED_SECTIONS.includes(section)) dependencyCount += entries.length
    for (const entry of entries) {
      for (const finding of classifyDependency(entry.name, entry.range, section, blocklist)) {
        push({ ...finding, pkg: entry.display })
      }
      if (OVERRIDE_SECTIONS.includes(section)) {
        push({
          rule: 'version-override',
          severity: 'low',
          pkg: entry.display,
          range: entry.range,
          message: `${section} forces ${entry.display}@${entry.range || 'unspecified'} across the tree, replacing the constraint a consumer chose.`,
        })
      }
    }
  }

  const scripts = manifest['scripts']
  if (typeof scripts === 'object' && scripts !== null && !Array.isArray(scripts)) {
    const pairs = Object.entries(scripts as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    let installHooks = 0
    for (const [hook, body] of pairs) {
      if (!INSTALL_HOOKS.includes(hook)) continue
      installHooks += 1
      push({
        rule: 'install-time-hook',
        severity: 'medium',
        pkg: pkgName || '(unnamed)',
        range: '',
        message: `"${hook}" runs arbitrary code whenever ${pkgName || 'this package'} is installed.`,
      })
      if (typeof body !== 'string') continue
      for (const signature of RISKY_SCRIPT_SIGNATURES) {
        if (signature.pattern.test(body)) {
          push({
            rule: signature.rule,
            severity: 'high',
            pkg: pkgName || hook,
            range: '',
            message: `"${hook}" script ${signature.message}. Evidence: ${clip(redact(body))}`,
          })
        }
      }
    }
    if (installHooks > 2) {
      push({
        rule: 'multiple-install-hooks',
        severity: 'medium',
        pkg: pkgName || '(unnamed)',
        range: '',
        message: `${installHooks} install-time hooks is unusual for a library; each one is another code-execution entry point.`,
      })
    }
  }

  findings.sort((a, b) => {
    if (a.severity !== b.severity) return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
    if (a.pkg !== b.pkg) return a.pkg < b.pkg ? -1 : 1
    return a.rule < b.rule ? -1 : a.rule > b.rule ? 1 : 0
  })
  return { ok: true, error: '', pkg: pkgName, dependencyCount, counts, findings }
}

const SEVERITY_SCHEMA = {
  type: 'string',
  required: true,
  enum: ['high', 'medium', 'low'],
  description: 'Severity assigned by this signature.',
} as const

const COUNTS_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: true,
  description: 'Finding totals by severity, including findings dropped by the report cap.',
  properties: {
    high: { type: 'integer', required: true, description: 'High severity findings.' },
    medium: { type: 'integer', required: true, description: 'Medium severity findings.' },
    low: { type: 'integer', required: true, description: 'Low severity findings.' },
  },
} as const

const scanOutput = {
  type: 'object',
  additionalProperties: false,
  properties: {
    scanned: { type: 'integer', required: true, description: 'Number of files actually pattern-matched.' },
    counts: COUNTS_SCHEMA,
    truncated: { type: 'boolean', required: true, description: 'True when the report cap dropped findings.' },
    findings: {
      type: 'array',
      required: true,
      description: 'Findings ordered by path, then line, then severity, then rule.',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          rule: { type: 'string', required: true, description: 'Stable signature id, for example "aws-access-key-id".' },
          kind: { type: 'string', required: true, enum: ['secret', 'risky-pattern'], description: 'Credential material or a risky code shape.' },
          severity: SEVERITY_SCHEMA,
          path: { type: 'string', required: true, description: 'Path the caller supplied for this file.' },
          line: { type: 'integer', required: true, description: 'One-based line number of the match.' },
          evidence: { type: 'string', required: true, description: 'Matched text; credential matches come back redacted.' },
          message: { type: 'string', required: true, description: 'What the hit means and how to remediate it.' },
        },
      },
    },
    skipped: {
      type: 'array',
      required: true,
      description: 'Files not scanned and why (over budget, binary, or non-string content).',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          path: { type: 'string', required: true, description: 'Path of the skipped file.' },
          reason: { type: 'string', required: true, description: 'Why it was skipped.' },
        },
      },
    },
  },
} as const

const auditOutput = {
  type: 'object',
  additionalProperties: false,
  properties: {
    ok: { type: 'boolean', required: true, description: 'True when the manifest parsed as a JSON object.' },
    error: { type: 'string', required: true, description: 'Parse failure text; empty when ok.' },
    pkg: { type: 'string', required: true, description: 'Declared package name, or empty when absent.' },
    dependencyCount: { type: 'integer', required: true, description: 'Dependency entries inspected in dependencies/devDependencies/optionalDependencies.' },
    counts: COUNTS_SCHEMA,
    findings: {
      type: 'array',
      required: true,
      description: 'Heuristic findings, most severe first.',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          rule: { type: 'string', required: true, description: 'Heuristic id, for example "possible-typosquat".' },
          severity: SEVERITY_SCHEMA,
          pkg: { type: 'string', required: true, description: 'Dependency the finding is about; "(unnamed)" or the package itself for lifecycle findings.' },
          range: { type: 'string', required: true, description: 'Declared version range; empty for lifecycle findings.' },
          message: { type: 'string', required: true, description: 'Explanation and remediation.' },
        },
      },
    },
  },
} as const

/**
 * Register the security audit tools on `ctx.tools`.
 * @param ctx - registrant context carrying the tool registry.
 * @param config - deployment's explicit auditor policy.
 */
export function apply(ctx: Context, config: Config): void {
  ctx.tools.register(defineTool({
    name: 'scan_secrets',
    description:
      'Scan a caller-supplied map of file contents for leaked secrets (AWS keys, private key ' +
      'blocks, GitHub/GitLab/Slack/Stripe/npm/PyPI/SendGrid/Twilio/Google/LLM tokens, JWTs, ' +
      'inline URL credentials, hardcoded secret assignments) and for risky code shapes ' +
      '(interpolated shell commands, shell=True, unsafe deserialization, SQL concatenation, ' +
      'disabled TLS verification, HTML sinks, path traversal, dynamic eval, weak password hashes). ' +
      'Pass files as {"relative/path": "full file text"} — the tool never reads the filesystem. ' +
      'Credential matches are returned redacted. maxBytes is a per-file UTF-8 budget; 0 means no limit.',
    parameters: {
      files: {
        type: 'object',
        required: true,
        additionalProperties: true,
        description: "Map of file path to that file's full text content.",
      },
      maxBytes: {
        type: 'integer',
        required: true,
        description: 'Per-file UTF-8 budget. Larger files are skipped and listed; pass 0 for no limit.',
      },
    },
    output: {
      schema: scanOutput,
      render: (_args, value) => [{
        type: 'text',
        text: value.findings.length === 0 && !value.truncated
          ? `scan_secrets: nothing flagged across ${value.scanned} file(s).`
          : [
              `scan_secrets: ${value.counts.high} high, ${value.counts.medium} medium, ${value.counts.low} low across ${value.scanned} file(s).`,
              ...value.findings.map(f => `- [${f.severity}/${f.kind}] ${f.path}:${f.line} ${f.rule} — ${f.evidence}`),
              ...(value.skipped.length === 0 ? [] : [`skipped: ${value.skipped.map(s => `${s.path} (${s.reason})`).join(', ')}`]),
              ...(value.truncated ? ['report cap reached; remaining findings are counted only'] : []),
            ].join('\n'),
      }],
    },
    isConcurrencySafe: () => true,
    execute(args) {
      const budget = Number.isFinite(args.maxBytes) ? args.maxBytes : config.maxBytes
      const files = args.files as unknown as Record<string, unknown>
      return Promise.resolve(scanFiles(files, budget, config.maxFindings, new Set(config.disabledRules)))
    },
  }))

  ctx.tools.register(defineTool({
    name: 'audit_package',
    description:
      'Offline heuristic audit of one package.json body: pass the raw JSON text as ' +
      'packageJsonText. It flags packages with recorded supply-chain incidents, names one or ' +
      'two edits away from popular packages (typosquat suspicion), plaintext-HTTP and git ' +
      'dependency sources, unpinned "*" / "latest" ranges, forced resolutions or overrides, ' +
      'deployment-blocklisted names, install-time lifecycle hooks, and dangerous hook bodies ' +
      '(curl piped to a shell, decoded blobs, reverse shells, encoded PowerShell). It fetches ' +
      'no advisories and runs no package manager. Pass includeDev=false to skip devDependencies.',
    parameters: {
      packageJsonText: {
        type: 'string',
        required: true,
        description: 'The complete raw contents of a package.json file.',
      },
      includeDev: {
        type: 'boolean',
        required: true,
        description: 'Also audit devDependencies. When omitted, the plugin configuration decides.',
      },
    },
    output: {
      schema: auditOutput,
      render: (_args, value) => [{
        type: 'text',
        text: !value.ok
          ? `audit_package: cannot use this manifest — ${value.error}`
          : value.findings.length === 0
            ? `audit_package: ${value.pkg || 'manifest'} — nothing flagged across ${value.dependencyCount} dependency entrie(s).`
            : [
                `audit_package: ${value.pkg || 'manifest'} — ${value.counts.high} high, ${value.counts.medium} medium, ${value.counts.low} low across ${value.dependencyCount} dependency entrie(s).`,
                ...value.findings.map(f => `- [${f.severity}] ${f.rule} ${f.pkg}${f.range ? `@${f.range}` : ''}: ${f.message}`),
              ].join('\n'),
      }],
    },
    isConcurrencySafe: () => true,
    execute(args) {
      const includeDev = typeof args.includeDev === 'boolean' ? args.includeDev : config.includeDevDependencies
      return Promise.resolve(auditPackage(args.packageJsonText, includeDev, config.extraRiskyPackages))
    },
  }))
}
