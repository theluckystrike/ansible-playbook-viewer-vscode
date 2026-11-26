'use strict';
// View model for Ansible Playbook Viewer: pagination, host/tag/search filter, plays, variables and findings.

class AnsibleViewModel {
  constructor(parsed, name, fileSize) {
    this.parsed = parsed;
    this.name = name;
    this.fileSize = fileSize;
    this.filter = { text: '', status: '' };
    this.filtered = parsed.rows.slice();
  }

  summary() {
    const p = this.parsed;
    const s = p.stats;
    return {
      name: this.name,
      fileKind: p.fileKind,
      fileSize: this.fileSize,
      totalLines: p.totalLines,
      playCount: s.playCount,
      taskCount: s.taskCount,
      handlerCount: s.handlerCount,
      roleCount: s.roleCount,
      variableCount: s.variableCount,
      errorCount: s.errorCount,
      warningCount: s.warningCount,
      plays: p.plays,
      variables: p.variables,
      findings: p.findings,
    };
  }

  totalCount() {
    return this.parsed.rows.length;
  }

  count() {
    return this.filtered.length;
  }

  setFilter(f) {
    const text = f && typeof f.text === 'string' ? f.text.trim().toLowerCase() : '';
    const status = f && typeof f.status === 'string' ? f.status.trim() : '';
    this.filter = { text, status };
    this.filtered = this.parsed.rows.filter((r) => {
      if (status === 'error' && r.status !== 'error') return false;
      if (status === 'warning' && r.status !== 'warning') return false;
      if (status === 'ok' && r.status !== 'ok') return false;
      if (status === 'become' && !r.become) return false;
      if (status === 'handler' && r.kind !== 'handler') return false;
      if (status === 'role' && r.kind !== 'role') return false;
      if (text) {
        const hay = `${r.kind} ${r.play} ${r.hosts} ${r.name} ${r.module} ${r.tags.join(' ')} ${r.when}`.toLowerCase();
        if (!hay.includes(text)) return false;
      }
      return true;
    });
    return this.filtered.length;
  }

  rows(from, limit) {
    const start = Math.max(0, Number(from) || 0);
    const n = Math.max(1, Math.min(500, Number(limit) || 100));
    return this.filtered.slice(start, start + n).map((r) => ({
      index: r.index,
      line: r.line,
      kind: r.kind,
      play: r.play,
      hosts: r.hosts,
      name: r.name,
      module: r.module,
      tags: r.tags,
      become: r.become,
      errorCount: r.errorCount,
      warningCount: r.warningCount,
      status: r.status,
    }));
  }

  detail(index) {
    const r = this.parsed.rows.find((x) => x.index === index) || this.parsed.rows[0] || null;
    if (!r) return null;
    return {
      index: r.index,
      line: r.line,
      kind: r.kind,
      play: r.play,
      hosts: r.hosts,
      name: r.name,
      module: r.module,
      tags: r.tags,
      become: r.become,
      when: r.when,
      changedWhen: r.changedWhen,
      ignoreErrors: r.ignoreErrors,
      notify: r.notify,
      status: r.status,
      findings: r.findings,
      attrs: r.attrs,
    };
  }
}

module.exports = { AnsibleViewModel };
