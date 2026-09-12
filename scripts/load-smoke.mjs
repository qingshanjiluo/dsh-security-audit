/**
 * Loads the built artifact and asserts it exports the Cordis function-plugin
 * face the harness loader requires, then mounts it against a stub registry.
 * Run after `npm run build`.
 * @module
 */
import assert from 'node:assert/strict'

const mod = await import(new URL('../lib/index.js', import.meta.url).href)

assert.equal(mod.name, 'dsh-security-audit', 'plugin name export')
assert.deepEqual(mod.inject, ['tools'], 'inject declares the tools service')
assert.equal(typeof mod.apply, 'function', 'apply is a function')
assert.ok(mod.Config, 'Config schema export present')
assert.equal(mod.Config({}).maxBytes, 262144, 'Config supplies the maxBytes default')
assert.deepEqual(mod.Config({}).extraRiskyPackages, [], 'Config supplies an empty blocklist default')

const registered = []
mod.apply({ tools: { register: def => registered.push(def) } }, mod.Config({}))

assert.deepEqual(
  registered.map(t => t.name).sort(),
  ['audit_package', 'scan_secrets'],
  'both documented tools register',
)
for (const tool of registered) {
  assert.equal(typeof tool.execute, 'function', `${tool.name} executes`)
  assert.equal(typeof tool.output.render, 'function', `${tool.name} renders`)
  assert.equal(typeof tool.isConcurrencySafe, 'function', `${tool.name} classifies concurrency`)
  assert.ok(tool.description.length > 60, `${tool.name} carries a model-facing description`)
}

// Behaviour probe straight out of the built artifact: a planted key must be
// found, redacted, and never echoed back verbatim.
const scan = await registered.find(t => t.name === 'scan_secrets').execute({
  files: { 'src/db.ts': 'const key = "AKIAIOSFODNN7EXAMPLE"' },
  maxBytes: 4096,
}, {})
assert.equal(scan.scanned, 1, 'built artifact scans the supplied file')
assert.equal(scan.findings.length, 1, 'built artifact finds the planted key')
assert.equal(scan.findings[0].rule, 'aws-access-key-id', 'built artifact names the rule')
assert.ok(!JSON.stringify(scan).includes('AKIAIOSFODNN7EXAMPLE'), 'built artifact redacts the secret')

const audit = await registered.find(t => t.name === 'audit_package').execute({
  packageJsonText: JSON.stringify({ name: 'probe', dependencies: { 'event-stream': '^3.3.4' } }),
  includeDev: true,
}, {})
assert.equal(audit.ok, true, 'built artifact parses the manifest')
assert.ok(audit.findings.some(f => f.rule === 'known-risky-package'), 'built artifact flags the known-risky package')

console.log('load-smoke: ok —', registered.length, 'tools registered from built artifact')
