'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const {
  parseAnsible,
  buildAuditMarkdown,
  buildDiffMarkdown,
  buildRunbookCsv,
  buildRunbookMarkdown,
} = require('../src/ansible');
const { AnsibleViewModel } = require('../src/view');
const { editorHtml, csp } = require('../src/html');

test('parses sample site.playbook.yml with plays, roles, tasks, handlers, vars and findings', () => {
  const buf = fs.readFileSync(path.join(__dirname, '..', 'samples', 'site.playbook.yml'));
  const parsed = parseAnsible(buf, 'site.playbook.yml');
  assert.equal(parsed.stats.playCount, 1);
  assert.equal(parsed.stats.roleCount, 2);
  assert.equal(parsed.stats.taskCount, 3);
  assert.equal(parsed.stats.handlerCount, 2);
  assert.ok(parsed.stats.variableCount >= 2);

  const rules = new Set(parsed.findings.map((f) => f.rule));
  assert.ok(rules.has('global-become-root'));
  assert.ok(rules.has('plaintext-secret'));
  assert.ok(rules.has('shell-no-changed-when'));
  assert.ok(rules.has('ignore-errors'));
});

test('parses INI inventory with groups, hosts, vars and plaintext secret detection', () => {
  const ini = [
    '[webservers]',
    'web1.example.com ansible_user=deploy ansible_password=HardcodedSshPass99',
    'web2.example.com ansible_user=deploy',
    '[webservers:vars]',
    'http_port=8080',
  ].join('\n');
  const parsed = parseAnsible(ini, 'inventory.ini');
  assert.equal(parsed.fileKind, 'inventory');
  assert.equal(parsed.stats.playCount, 1);
  assert.equal(parsed.stats.taskCount, 2);
  assert.ok(parsed.findings.some((f) => f.rule === 'plaintext-secret'));
});

test('passes hardened playbook with zero findings', () => {
  const cleanYaml = [
    '---',
    '- name: Hardened web setup',
    '  hosts: webservers',
    '  tasks:',
    '    - name: Install nginx',
    '      ansible.builtin.apt:',
    '        name: nginx',
    '        state: present',
    '    - name: Check status',
    '      ansible.builtin.command: nginx -t',
    '      changed_when: false',
  ].join('\n');
  const parsed = parseAnsible(cleanYaml, 'playbook.yml');
  assert.equal(parsed.findings.length, 0);
});

test('AnsibleViewModel filters by become, role, handler, warning and search text', () => {
  const buf = fs.readFileSync(path.join(__dirname, '..', 'samples', 'site.playbook.yml'));
  const parsed = parseAnsible(buf, 'site.playbook.yml');
  const vm = new AnsibleViewModel(parsed, 'site.playbook.yml', buf.length);
  assert.equal(vm.totalCount(), 7);
  assert.equal(vm.setFilter({ text: '', status: 'role' }), 2);
  assert.equal(vm.setFilter({ text: '', status: 'handler' }), 2);
  assert.equal(vm.setFilter({ text: 'migrate', status: '' }), 1);
  const det = vm.detail(1);
  assert.ok(det && det.kind === 'role');
});

test('Pro report builders output audit, diff, CSV and runbook Markdown', () => {
  const buf = fs.readFileSync(path.join(__dirname, '..', 'samples', 'site.playbook.yml'));
  const left = parseAnsible(buf, 'site.playbook.yml');
  const right = parseAnsible('---\n- name: Configure web tier\n  hosts: webservers\n  tasks:\n    - name: Install nginx package\n      ansible.builtin.apt:\n        name: nginx\n        state: present\n', 'clean.yml');
  const audit = buildAuditMarkdown([{ fileName: 'site.playbook.yml', parsed: left }]);
  assert.match(audit, /Ansible Playbook Idempotency & Security Audit/);
  assert.match(audit, /shell-no-changed-when/);
  const diff = buildDiffMarkdown('site.playbook.yml', left, 'clean.yml', right);
  assert.match(diff, /Ansible Playbook & Inventory Comparison Report/);
  assert.match(diff, /RESOLVED/);
  const csv = buildRunbookCsv(left);
  assert.match(csv, /^kind,line,play,hosts,name,module,become,tags,status/);
  const rep = buildRunbookMarkdown(left, 'site.playbook.yml');
  assert.match(rep, /Ansible Runbook: site.playbook.yml/);
});

test('editorHtml enforces strict CSP with nonce and no unsafe-inline', () => {
  const html = editorHtml({ cspSource: 'vscode-webview://test', script: 'v.js', styleUri: 'v.css', title: 'site.playbook.yml', nonce: 'ans123' });
  assert.match(html, /default-src 'none'/);
  assert.match(html, /script-src 'nonce-ans123'/);
  assert.doesNotMatch(csp('vscode-webview://test', 'ans123'), /unsafe-inline/);
});
