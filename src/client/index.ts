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
  ctx.effect?.(() => ctx.locale?.register?.(NS, { zh, en }), `dsh-${NS}: locale`);
  ctx.effect?.(() => {
    ctx.slots?.inject?.('settings.plugin.item', function* () {
      yield ctx.slots.register({ name: 'settings.plugin.item', key: NS, locale: NS, inject: () => ({}) }, Card);
    });
  }, `dsh-${NS}: settings`);
}

function Card(props: any) {
  const { scope, t } = props;
  const [open, setOpen] = React.useState(false);
  const s = { background: '#1a1a2e', color: '#e0e0e0', borderRadius: '8px', padding: '12px', marginBottom: '8px', border: '1px solid #333' } as React.CSSProperties;
  const row = { display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 0', cursor: 'pointer', borderRadius: '4px', transition: 'background 0.15s' } as React.CSSProperties;
  const label = { display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', fontSize: '13px', marginBottom: '6px' } as React.CSSProperties;

  return React.createElement('li', { className: `dsh-${NS}-card`, style: s },
    React.createElement('div', { style: row, onClick: () => setOpen(!open), onMouseEnter: (e: any) => e.currentTarget.style.background = '#252540', onMouseLeave: (e: any) => e.currentTarget.style.background = 'transparent' },
      React.createElement('div', null,
        React.createElement('strong', { style: { fontSize: '14px' } }, '\uD83D\uDD12 ', t('title')),
        React.createElement('p', { style: { margin: '2px 0 0', fontSize: '12px', color: '#888' } }, t('description')),
      ),
      React.createElement('span', { style: { fontSize: '12px', color: '#888' } }, open ? '\u25B2' : '\u25BC'),
    ),
    open ? React.createElement('div', { style: { padding: '8px 0', borderTop: '1px solid #333' } },
      React.createElement('label', { style: label },
        React.createElement('input', { type: 'checkbox', checked: scope?.get?.('enabled') ?? true, onChange: (e: any) => scope?.set?.('enabled', e.target.checked) }),
        t('enabled'),
      ),
      React.createElement('label', { style: label },
        React.createElement('input', { type: 'checkbox', checked: scope?.get?.('scanSecrets') ?? true, onChange: (e: any) => scope?.set?.('scanSecrets', e.target.checked) }),
        t('scanSecrets'),
      ),
      React.createElement('label', { style: label },
        React.createElement('input', { type: 'checkbox', checked: scope?.get?.('scanVulnerabilities') ?? true, onChange: (e: any) => scope?.set?.('scanVulnerabilities', e.target.checked) }),
        t('scanVulnerabilities'),
      ),
      React.createElement('label', { style: { ...label, marginBottom: 0 } },
        React.createElement('input', { type: 'checkbox', checked: scope?.get?.('checkLicenses') ?? true, onChange: (e: any) => scope?.set?.('checkLicenses', e.target.checked) }),
        t('checkLicenses'),
      ),
      React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginTop: '6px' } },
        React.createElement('label', { style: { fontSize: '13px', minWidth: '120px' } }, t('maxFileSize')),
        React.createElement('input', { type: 'number', value: scope?.get?.('maxFileSize') ?? 1048576, onChange: (e: any) => scope?.set?.('maxFileSize', Number(e.target.value)), style: { width: '100px', padding: '4px 8px', borderRadius: '4px', border: '1px solid #444', background: '#0d0d1a', color: '#e0e0e0', fontSize: '13px' } }),
      ),
    ) : null,
  );
}
