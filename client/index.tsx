import React from 'react';
import { createSettingsCard } from '@deepseek-ai/dsh-settings';

export default createSettingsCard({
  title: 'security-audit',
  description: '安全审计插件',
  config: [
    { key: 'enabled', type: 'boolean', label: '启用插件', default: true },
    { key: 'scanSecrets', type: 'boolean', label: '扫描密钥泄露', default: true },
    { key: 'scanVulnerabilities', type: 'boolean', label: '扫描依赖漏洞', default: true },
    { key: 'checkLicenses', type: 'boolean', label: '检查许可证合规', default: true },
    { key: 'maxFileSize', type: 'number', label: '最大文件大小(bytes)', default: 102400 },
  ],
});
