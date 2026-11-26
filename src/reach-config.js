'use strict';
module.exports = {
  prefix: 'zovoAns',
  triesKey: 'zovoAns.proTrial',
  slot: '#protools',
  tools: [
    { id: 'auditPlaybook', title: 'Audit Ansible playbook idempotency and security', command: 'zovoAns.auditPlaybook' },
    { id: 'diffPlaybooks', title: 'Compare two Ansible playbooks or inventories', command: 'zovoAns.diffPlaybooks' },
    { id: 'exportRunbook', title: 'Export Markdown task runbook and inventory CSV', command: 'zovoAns.exportRunbook' },
  ],
};
