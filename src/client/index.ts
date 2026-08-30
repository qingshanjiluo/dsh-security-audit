/**
 * dsh-security-audit 客户端 — 设置卡片
 */

import React from 'react';

const NS = 'security-audit';

const zh = {
  title: '安全审计',
  description: '依赖漏洞扫描、密钥泄露检测、许可证合规检查',
  enabled: '启用插件',
  scanSecrets: '扫描密钥泄露',
  scanVulnerabilities: '扫描依赖漏洞',
  checkLicenses: '检查许可证合规',
  maxFileSize: '最大文件大小（字节）',
};

const en = {
  title: 'Security Audit',
  description: 'Dependency vulnerability scanning, secret detection, license compliance',
  enabled: 'Enable plugin',
  scanSecrets: 'Scan for secrets',
  scanVulnerabilities: 'Scan vulnerabilities',
  checkLicenses: 'Check license compliance',
  maxFileSize: 'Max file size (bytes)',
};

export const inject = ['settingsScope', 'slots', 'locale'];

export function apply(ctx: any) {
  const t = ctx.locale?.bind(NS) || ((key: string) => (zh as any)[key] || key);

  ctx.effect?.(() => {
    ctx.locale?.register?.(NS, { zh, en });
  }, 'dsh-security-audit: locale');

  ctx.effect?.(() => {
    ctx.slots?.inject?.('settings.plugin.item', function* () {
      yield ctx.slots.register(
        {
          name: 'settings.plugin.item',
          key: NS,
          locale: NS,
          inject: () => ({}),
        },
        SecurityAuditCard,
      );
    });
  }, 'dsh-security-audit: settings card');
}

function SecurityAuditCard(props: any) {
  const { scope, t } = props;
  const [open, setOpen] = React.useState(false);

  return React.createElement('li', { className: 'dsh-security-audit-card' },
    React.createElement('div', {
      style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 0', cursor: 'pointer' },
      onClick: () => setOpen(!open),
    },
      React.createElement('div', null,
        React.createElement('strong', null, '🔒 ', t('title')),
        React.createElement('p', { style: { margin: '2px 0 0', fontSize: '12px', color: '#888' } }, t('description')),
      ),
      React.createElement('span', { style: { fontSize: '12px', color: '#888' } }, open ? '▲' : '▼'),
    ),
    open ? React.createElement('div', { style: { padding: '8px 0', borderTop: '1px solid #333' } },
      React.createElement('label', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', cursor: 'pointer' } },
        React.createElement('input', {
          type: 'checkbox',
          checked: scope?.get?.('enabled') ?? true,
          onChange: (e: any) => scope?.set?.('enabled', e.target.checked),
        }),
        t('enabled'),
      ),
      React.createElement('label', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', cursor: 'pointer' } },
        React.createElement('input', {
          type: 'checkbox',
          checked: scope?.get?.('scanSecrets') ?? true,
          onChange: (e: any) => scope?.set?.('scanSecrets', e.target.checked),
        }),
        t('scanSecrets'),
      ),
      React.createElement('label', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', cursor: 'pointer' } },
        React.createElement('input', {
          type: 'checkbox',
          checked: scope?.get?.('scanVulnerabilities') ?? true,
          onChange: (e: any) => scope?.set?.('scanVulnerabilities', e.target.checked),
        }),
        t('scanVulnerabilities'),
      ),
      React.createElement('label', { style: { display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' } },
        React.createElement('input', {
          type: 'checkbox',
          checked: scope?.get?.('checkLicenses') ?? true,
          onChange: (e: any) => scope?.set?.('checkLicenses', e.target.checked),
        }),
        t('checkLicenses'),
      ),
    ) : null,
  );
}
