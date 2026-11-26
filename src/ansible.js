'use strict';
// Offline Ansible Playbook YAML & INI Inventory parser and static idempotency/security analyzer.
// Zero Python, zero ansible-lint, zero cloud calls, plain JavaScript.

const TASK_META_KEYS = new Set([
  'name', 'when', 'tags', 'become', 'become_user', 'become_method', 'changed_when',
  'failed_when', 'ignore_errors', 'notify', 'register', 'loop', 'with_items',
  'with_dict', 'with_fileglob', 'vars', 'environment', 'delegate_to', 'run_once',
  'retries', 'delay', 'until', 'listen', 'no_log', 'block', 'rescue', 'always',
  'check_mode', 'diff', 'args', 'collections',
]);

const SECRET_KEY_RE = /(password|passwd|secret|token|api_key|apikey|ansible_password|ansible_become_pass|ansible_ssh_pass|private_key|db_pass)/i;
const SHELL_MOD_RE = /^(?:ansible\.builtin\.)?(?:shell|command|raw)$/;

function unquote(v) {
  const s = String(v || '').trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  return s;
}

function isTruthy(v) {
  const s = unquote(v).toLowerCase();
  return s === 'true' || s === 'yes' || s === '1';
}

function stripYamlComment(line) {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === '#' && !inSingle && !inDouble && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i);
    }
  }
  return line;
}

function parseListInline(val) {
  const s = String(val || '').trim();
  if (s.startsWith('[') && s.endsWith(']')) {
    return s.slice(1, -1).split(',').map((x) => unquote(x)).filter(Boolean);
  }
  return s ? [unquote(s)] : [];
}

function extractJinjaVars(text, lineNo, varMap) {
  const re = /\{\{\s*([A-Za-z_][A-Za-z0-9_.-]*)/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const name = m[1];
    if (!varMap.has(name)) varMap.set(name, { name, kind: name.includes('vault') ? 'vault' : 'jinja', lines: [] });
    const entry = varMap.get(name);
    if (!entry.lines.includes(lineNo)) entry.lines.push(lineNo);
  }
  if (/!vault|\$ANSIBLE_VAULT/.test(text)) {
    if (!varMap.has('$ANSIBLE_VAULT')) varMap.set('$ANSIBLE_VAULT', { name: '$ANSIBLE_VAULT', kind: 'vault', lines: [] });
    const entry = varMap.get('$ANSIBLE_VAULT');
    if (!entry.lines.includes(lineNo)) entry.lines.push(lineNo);
  }
}

function checkPlaintextSecret(key, val, lineNo, scope, findings) {
  if (!SECRET_KEY_RE.test(key)) return null;
  const v = unquote(val);
  if (!v || v.includes('{{') || v.includes('!vault') || v.includes('$ANSIBLE_VAULT') || v === '|' || v === '>') return null;
  if (/^(changeme|example|placeholder|null|none|true|false)$/i.test(v) || v.length < 4) return null;
  const f = {
    severity: 'error',
    category: 'Secrets',
    rule: 'plaintext-secret',
    line: lineNo,
    section: scope,
    message: `Plaintext secret in "${key}" at ${scope}. Encrypt with ansible-vault or reference a vault variable.`,
  };
  findings.push(f);
  return f;
}

function parseInventoryIni(text, fileName) {
  const lines = text.split(/\r?\n/);
  const rows = [];
  const findings = [];
  const varMap = new Map();
  const groups = new Set();
  let curGroup = 'ungrouped';
  let curMode = 'hosts';

  for (let i = 0; i < lines.length; i += 1) {
    const lineNo = i + 1;
    const raw = lines[i].replace(/^\s+|\s+$/g, '');
    if (!raw || raw.startsWith('#') || raw.startsWith(';')) continue;
    extractJinjaVars(raw, lineNo, varMap);

    const sec = raw.match(/^\[([^\]]+)\]$/);
    if (sec) {
      const header = sec[1].trim();
      const parts = header.split(':');
      curGroup = parts[0];
      curMode = parts[1] || 'hosts';
      groups.add(curGroup);
      continue;
    }

    if (curMode === 'vars') {
      const kv = raw.match(/^([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(.+)$/);
      if (kv) {
        const key = kv[1];
        const val = kv[2].trim();
        if (!varMap.has(key)) varMap.set(key, { name: key, kind: key.includes('vault') ? 'vault' : 'group_var', lines: [lineNo] });
        const f = checkPlaintextSecret(key, val, lineNo, `[${curGroup}:vars]`, findings);
        rows.push({
          index: rows.length + 1,
          line: lineNo,
          kind: 'group_var',
          play: curGroup,
          hosts: curGroup,
          name: `${curGroup}:vars -> ${key}`,
          module: 'group_var',
          tags: [curGroup],
          become: false,
          when: '',
          changedWhen: '',
          ignoreErrors: false,
          notify: [],
          attrs: [{ key, value: SECRET_KEY_RE.test(key) ? '***REDACTED***' : val }],
          findings: f ? [f] : [],
        });
      }
      continue;
    }

    if (curMode === 'children') {
      rows.push({
        index: rows.length + 1,
        line: lineNo,
        kind: 'child_group',
        play: curGroup,
        hosts: raw,
        name: `${curGroup} -> ${raw}`,
        module: 'children',
        tags: [curGroup],
        become: false,
        when: '',
        changedWhen: '',
        ignoreErrors: false,
        notify: [],
        attrs: [{ key: 'parent', value: curGroup }, { key: 'child', value: raw }],
        findings: [],
      });
      continue;
    }

    // Host line: host_name key=val key2=val2
    const tokens = raw.split(/\s+/);
    const host = tokens[0];
    const attrs = [];
    const rowFindings = [];
    for (let t = 1; t < tokens.length; t += 1) {
      const eq = tokens[t].indexOf('=');
      if (eq > 0) {
        const k = tokens[t].slice(0, eq);
        const v = tokens[t].slice(eq + 1);
        const f = checkPlaintextSecret(k, v, lineNo, host, findings);
        if (f) rowFindings.push(f);
        attrs.push({ key: k, value: SECRET_KEY_RE.test(k) ? '***REDACTED***' : v });
      }
    }
    rows.push({
      index: rows.length + 1,
      line: lineNo,
      kind: 'host',
      play: curGroup,
      hosts: host,
      name: host,
      module: curGroup,
      tags: [curGroup],
      become: false,
      when: '',
      changedWhen: '',
      ignoreErrors: false,
      notify: [],
      attrs,
      findings: rowFindings,
    });
  }

  const normalized = rows.map((r) => {
    const errorCount = r.findings.filter((f) => f.severity === 'error').length;
    const warningCount = r.findings.filter((f) => f.severity === 'warning').length;
    return {
      ...r,
      errorCount,
      warningCount,
      status: errorCount > 0 ? 'error' : (warningCount > 0 ? 'warning' : 'ok'),
    };
  });

  const variables = [...varMap.values()].sort((a, b) => a.name.localeCompare(b.name));
  return {
    fileName,
    fileKind: 'inventory',
    totalLines: lines.length,
    plays: [...groups].map((g, idx) => ({ index: idx + 1, line: 1, name: g, hosts: g, become: false, roles: [], tags: [g] })),
    roles: [],
    variables,
    rows: normalized,
    findings,
    stats: {
      playCount: groups.size,
      taskCount: normalized.filter((r) => r.kind === 'host').length,
      handlerCount: 0,
      roleCount: 0,
      variableCount: variables.length,
      errorCount: findings.filter((f) => f.severity === 'error').length,
      warningCount: findings.filter((f) => f.severity === 'warning').length,
    },
  };
}

function parseAnsible(input, fileName = 'playbook.yml') {
  const text = Buffer.isBuffer(input) ? input.toString('utf8') : String(input || '');
  if (/\.ini$/i.test(fileName)) {
    return parseInventoryIni(text, fileName);
  }

  const lines = text.split(/\r?\n/);
  const plays = [];
  const roles = [];
  const rows = [];
  const findings = [];
  const varMap = new Map();

  let curPlay = null;
  let section = null; // 'tasks' | 'pre_tasks' | 'post_tasks' | 'handlers' | 'roles' | 'vars' | 'tags'
  let sectionIndent = -1;
  let curTask = null;
  let taskIndent = -1;

  function finalizeTask() {
    if (!curTask) return;
    const t = curTask;
    curTask = null;
    if (!t.module) t.module = 'task';
    if (SHELL_MOD_RE.test(t.module) && !t.changedWhen) {
      const f = {
        severity: 'warning',
        category: 'Idempotency',
        rule: 'shell-no-changed-when',
        line: t.line,
        section: t.name,
        message: `Task "${t.name}" uses "${t.module}" without changed_when. Add changed_when to keep playbook runs idempotent.`,
      };
      findings.push(f);
      t.findings.push(f);
    }
    if (t.ignoreErrors) {
      const f = {
        severity: 'warning',
        category: 'Reliability',
        rule: 'ignore-errors',
        line: t.line,
        section: t.name,
        message: `Task "${t.name}" sets ignore_errors: true, which silently hides failures. Prefer failed_when or block/rescue.`,
      };
      findings.push(f);
      t.findings.push(f);
    }
    if (t.hasLatestState) {
      const f = {
        severity: 'warning',
        category: 'Idempotency',
        rule: 'latest-package',
        line: t.line,
        section: t.name,
        message: `Task "${t.name}" uses state: latest, causing non-deterministic upgrades across runs.`,
      };
      findings.push(f);
      t.findings.push(f);
    }
    rows.push(t);
  }

  for (let i = 0; i < lines.length; i += 1) {
    const lineNo = i + 1;
    const raw = stripYamlComment(lines[i]);
    if (!raw.trim() || raw.trim() === '---' || raw.trim() === '...') continue;
    extractJinjaVars(raw, lineNo, varMap);

    const indent = raw.match(/^(\s*)/)[1].length;
    const trimmed = raw.trim();

    // Top-level play entry: "- name:" or "- hosts:" at indent 0 (or 2 if wrapped)
    if (indent <= 2 && trimmed.startsWith('- ') && (!curPlay || indent <= curPlay.indent)) {
      finalizeTask();
      const rest = trimmed.slice(2).trim();
      const kv = rest.match(/^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/);
      if (kv && (kv[1] === 'name' || kv[1] === 'hosts' || kv[1] === 'import_playbook')) {
        curPlay = {
          index: plays.length + 1,
          line: lineNo,
          indent,
          name: kv[1] === 'name' ? unquote(kv[2]) : `Play ${plays.length + 1}`,
          hosts: kv[1] === 'hosts' ? unquote(kv[2]) : '(unset)',
          become: false,
          roles: [],
          tags: [],
        };
        plays.push(curPlay);
        section = null;
        sectionIndent = -1;
        continue;
      }
    }

    if (!curPlay) continue;

    // Play-level property (directly inside play, indent <= curPlay.indent + 2)
    if (indent <= curPlay.indent + 2 && !trimmed.startsWith('-')) {
      finalizeTask();
      const kv = trimmed.match(/^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/);
      if (kv) {
        const key = kv[1];
        const val = kv[2].trim();
        if (key === 'name') curPlay.name = unquote(val);
        else if (key === 'hosts') curPlay.hosts = unquote(val);
        else if (key === 'become') {
          curPlay.become = isTruthy(val);
          if (curPlay.become) {
            findings.push({
              severity: 'warning',
              category: 'Privilege',
              rule: 'global-become-root',
              line: lineNo,
              section: curPlay.name,
              message: `Play "${curPlay.name}" enables global become: true across all tasks. Scope become to individual tasks when possible.`,
            });
          }
        } else if (key === 'tags') {
          curPlay.tags.push(...parseListInline(val));
          section = val ? null : 'tags';
          sectionIndent = indent;
        } else if (['tasks', 'pre_tasks', 'post_tasks', 'handlers', 'roles', 'vars'].includes(key)) {
          section = key;
          sectionIndent = indent;
        } else {
          section = null;
        }
      }
      continue;
    }

    if (section === 'vars' && indent > sectionIndent) {
      const kv = trimmed.match(/^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/);
      if (kv) {
        const k = kv[1];
        const v = kv[2].trim();
        if (!varMap.has(k)) varMap.set(k, { name: k, kind: k.includes('vault') ? 'vault' : 'play_var', lines: [lineNo] });
        checkPlaintextSecret(k, v, lineNo, `${curPlay.name} vars.${k}`, findings);
      }
      continue;
    }

    if (section === 'roles' && indent > sectionIndent) {
      if (trimmed.startsWith('- ')) {
        const rest = trimmed.slice(2).trim();
        const roleName = rest.startsWith('role:') ? unquote(rest.slice(5)) : unquote(rest);
        if (roleName) {
          curPlay.roles.push(roleName);
          roles.push({ line: lineNo, play: curPlay.name, hosts: curPlay.hosts, role: roleName });
          rows.push({
            index: rows.length + 1,
            line: lineNo,
            kind: 'role',
            play: curPlay.name,
            hosts: curPlay.hosts,
            name: `role: ${roleName}`,
            module: 'role',
            tags: curPlay.tags.slice(),
            become: curPlay.become,
            when: '',
            changedWhen: '',
            ignoreErrors: false,
            notify: [],
            attrs: [{ key: 'role', value: roleName }],
            findings: [],
          });
        }
      }
      continue;
    }

    if (section === 'tags' && indent > sectionIndent && trimmed.startsWith('- ')) {
      curPlay.tags.push(unquote(trimmed.slice(2)));
      continue;
    }

    if (['tasks', 'pre_tasks', 'post_tasks', 'handlers'].includes(section) && indent > sectionIndent) {
      const isItem = trimmed.startsWith('- ');
      if (isItem && (taskIndent === -1 || indent <= taskIndent)) {
        finalizeTask();
        taskIndent = indent;
        const kind = section === 'handlers' ? 'handler' : 'task';
        curTask = {
          index: rows.length + 1,
          line: lineNo,
          kind,
          play: curPlay.name,
          hosts: curPlay.hosts,
          name: `${kind}@${lineNo}`,
          module: '',
          tags: curPlay.tags.slice(),
          become: curPlay.become,
          when: '',
          changedWhen: '',
          ignoreErrors: false,
          hasLatestState: false,
          notify: [],
          attrs: [],
          findings: [],
        };
        const rest = trimmed.slice(2).trim();
        const kv = rest.match(/^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/);
        if (kv) {
          const k = kv[1];
          const v = kv[2].trim();
          if (k === 'name') curTask.name = unquote(v);
          else if (!TASK_META_KEYS.has(k)) {
            curTask.module = k;
            if (v) curTask.attrs.push({ key: k, value: v });
          }
        }
        continue;
      }

      if (curTask) {
        const kv = trimmed.match(/^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/);
        if (kv) {
          const k = kv[1];
          const v = kv[2].trim();
          const secFinding = checkPlaintextSecret(k, v, lineNo, curTask.name, findings);
          if (secFinding) curTask.findings.push(secFinding);

          if (k === 'name' && indent <= taskIndent + 2) curTask.name = unquote(v);
          else if (k === 'when') curTask.when = unquote(v);
          else if (k === 'changed_when') curTask.changedWhen = unquote(v) || 'set';
          else if (k === 'ignore_errors') curTask.ignoreErrors = isTruthy(v);
          else if (k === 'become') curTask.become = isTruthy(v);
          else if (k === 'tags') curTask.tags.push(...parseListInline(v));
          else if (k === 'notify') curTask.notify.push(...parseListInline(v));
          else if (k === 'state' && unquote(v).toLowerCase() === 'latest') curTask.hasLatestState = true;
          else if (!TASK_META_KEYS.has(k) && !curTask.module && indent <= taskIndent + 2) {
            curTask.module = k;
            if (v) curTask.attrs.push({ key: k, value: SECRET_KEY_RE.test(k) ? '***REDACTED***' : v });
          } else if (v) {
            curTask.attrs.push({ key: k, value: SECRET_KEY_RE.test(k) ? '***REDACTED***' : v });
          }
        }
      }
    }
  }
  finalizeTask();

  const normalized = rows.map((r, idx) => {
    const errorCount = r.findings.filter((f) => f.severity === 'error').length;
    const warningCount = r.findings.filter((f) => f.severity === 'warning').length;
    return {
      index: idx + 1,
      line: r.line,
      kind: r.kind,
      play: r.play,
      hosts: r.hosts,
      name: r.name,
      module: r.module,
      tags: [...new Set(r.tags)],
      become: r.become,
      when: r.when,
      changedWhen: r.changedWhen,
      ignoreErrors: r.ignoreErrors,
      notify: r.notify,
      attrs: r.attrs,
      findings: r.findings,
      errorCount,
      warningCount,
      status: errorCount > 0 ? 'error' : (warningCount > 0 ? 'warning' : 'ok'),
    };
  });

  const variables = [...varMap.values()].sort((a, b) => a.name.localeCompare(b.name));
  return {
    fileName,
    fileKind: 'playbook',
    totalLines: lines.length,
    plays,
    roles,
    variables,
    rows: normalized,
    findings,
    stats: {
      playCount: plays.length,
      taskCount: normalized.filter((r) => r.kind === 'task').length,
      handlerCount: normalized.filter((r) => r.kind === 'handler').length,
      roleCount: roles.length,
      variableCount: variables.length,
      errorCount: findings.filter((f) => f.severity === 'error').length,
      warningCount: findings.filter((f) => f.severity === 'warning').length,
    },
  };
}

function buildAuditMarkdown(entries) {
  const out = ['# Ansible Playbook Idempotency & Security Audit', ''];
  let totalErrors = 0;
  let totalWarnings = 0;
  for (const e of entries) {
    totalErrors += e.parsed.stats.errorCount;
    totalWarnings += e.parsed.stats.warningCount;
  }
  out.push(`- Files audited: **${entries.length}**`);
  out.push(`- Errors: **${totalErrors}** | Warnings: **${totalWarnings}**`, '');
  for (const e of entries) {
    const p = e.parsed;
    out.push(`## ${e.fileName}`);
    out.push(`Plays/Groups: ${p.stats.playCount} | Tasks/Hosts: ${p.stats.taskCount} | Handlers: ${p.stats.handlerCount} | Roles: ${p.stats.roleCount} | Vars: ${p.stats.variableCount}`, '');
    if (!p.findings.length) {
      out.push('No static idempotency or security findings.', '');
    } else {
      out.push('| Severity | Category | Rule | Line | Scope | Finding |');
      out.push('| --- | --- | --- | ---: | --- | --- |');
      for (const f of p.findings) {
        out.push(`| ${f.severity.toUpperCase()} | ${f.category} | \`${f.rule}\` | ${f.line} | \`${f.section}\` | ${f.message.replace(/\|/g, '\\|')} |`);
      }
      out.push('');
    }
  }
  return out.join('\n');
}

function buildDiffMarkdown(leftName, left, rightName, right) {
  const out = [
    '# Ansible Playbook & Inventory Comparison Report',
    '',
    `- Baseline: \`${leftName}\` (${left.stats.playCount} plays/groups, ${left.stats.taskCount} tasks/hosts, ${left.stats.errorCount} errors, ${left.stats.warningCount} warnings)`,
    `- Target: \`${rightName}\` (${right.stats.playCount} plays/groups, ${right.stats.taskCount} tasks/hosts, ${right.stats.errorCount} errors, ${right.stats.warningCount} warnings)`,
    '',
    '## Task / Host Changes',
    '',
    '| Item | Change | Baseline | Target |',
    '| --- | --- | --- | --- |',
  ];
  const lMap = new Map(left.rows.map((r) => [`${r.play}::${r.name}`, r]));
  const rMap = new Map(right.rows.map((r) => [`${r.play}::${r.name}`, r]));
  const keys = [...new Set([...lMap.keys(), ...rMap.keys()])].sort();
  let changes = 0;
  for (const k of keys) {
    const a = lMap.get(k);
    const b = rMap.get(k);
    if (!a && b) {
      changes += 1;
      out.push(`| \`${k}\` | ADDED | — | \`${b.module} (${b.hosts})\` |`);
    } else if (a && !b) {
      changes += 1;
      out.push(`| \`${k}\` | REMOVED | \`${a.module} (${a.hosts})\` | — |`);
    } else if (a && b && (a.module !== b.module || a.hosts !== b.hosts || a.become !== b.become || a.status !== b.status)) {
      changes += 1;
      out.push(`| \`${k}\` | CHANGED | \`${a.module} / become=${a.become}\` | \`${b.module} / become=${b.become}\` |`);
    }
  }
  if (!changes) out.push('| (none) | UNCHANGED | — | — |');
  const lRules = new Set(left.findings.map((f) => `${f.rule}@${f.section}`));
  const rRules = new Set(right.findings.map((f) => `${f.rule}@${f.section}`));
  const resolved = [...lRules].filter((x) => !rRules.has(x));
  const introduced = [...rRules].filter((x) => !lRules.has(x));
  out.push('', '## Finding Delta', '');
  out.push(`- RESOLVED: ${resolved.length ? resolved.map((x) => `\`${x}\``).join(', ') : 'none'}`);
  out.push(`- INTRODUCED: ${introduced.length ? introduced.map((x) => `\`${x}\``).join(', ') : 'none'}`, '');
  return out.join('\n');
}

function csvCell(v) {
  const s = String(v == null ? '' : v);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function buildRunbookCsv(parsed) {
  const lines = ['kind,line,play,hosts,name,module,become,tags,status'];
  for (const r of parsed.rows) {
    lines.push([
      r.kind,
      r.line,
      r.play,
      r.hosts,
      r.name,
      r.module,
      r.become ? 'true' : 'false',
      r.tags.join('; '),
      r.status,
    ].map(csvCell).join(','));
  }
  return lines.join('\n') + '\n';
}

function buildRunbookMarkdown(parsed, fileName) {
  const out = [
    `# Ansible Runbook: ${fileName}`,
    '',
    `- Plays / Groups: **${parsed.stats.playCount}** | Tasks / Hosts: **${parsed.stats.taskCount}** | Handlers: **${parsed.stats.handlerCount}** | Roles: **${parsed.stats.roleCount}**`,
    `- Variables / Vault refs: **${parsed.stats.variableCount}** | Findings: **${parsed.stats.errorCount} errors, ${parsed.stats.warningCount} warnings**`,
    '',
    '## Execution Table',
    '',
    '| Line | Kind | Play / Group | Hosts | Task / Entry | Module | Become | Tags | Status |',
    '| ---: | --- | --- | --- | --- | --- | --- | --- | --- |',
  ];
  for (const r of parsed.rows) {
    out.push(`| ${r.line} | ${r.kind} | ${r.play} | \`${r.hosts}\` | ${r.name} | \`${r.module}\` | ${r.become ? 'yes' : 'no'} | \`${r.tags.join(', ') || '-'}\` | ${r.status.toUpperCase()} |`);
  }
  out.push('');
  return out.join('\n');
}

module.exports = {
  parseAnsible,
  buildAuditMarkdown,
  buildDiffMarkdown,
  buildRunbookCsv,
  buildRunbookMarkdown,
};
