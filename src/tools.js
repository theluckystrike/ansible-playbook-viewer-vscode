'use strict';
// Pro tools for Ansible Playbook Viewer:
//   1. auditPlaybook: Offline Markdown idempotency & security audit.
//   2. diffPlaybooks: Compare two Ansible playbooks or inventories in Markdown.
//   3. exportRunbook: Non-destructive Markdown task & role runbook + CSV inventory.
const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const {
  parseAnsible,
  buildAuditMarkdown,
  buildDiffMarkdown,
  buildRunbookCsv,
  buildRunbookMarkdown,
} = require('./ansible');

const ANS_RE = /(\.ya?ml$|\.ini$)/i;

function uniquePath(targetPath) {
  if (!fs.existsSync(targetPath)) return targetPath;
  const dir = path.dirname(targetPath);
  const ext = path.extname(targetPath);
  const base = path.basename(targetPath, ext);
  for (let i = 1; i < 10000; i += 1) {
    const cand = path.join(dir, `${base}-${i}${ext}`);
    if (!fs.existsSync(cand)) return cand;
  }
  return path.join(dir, `${base}-${Date.now()}${ext}`);
}

async function resolveTargetUri(uri, provider, openLabel = 'Select Ansible playbook or inventory file') {
  if (uri && uri.scheme) return uri;
  if (provider && provider.active && provider.active.uri) return provider.active.uri;
  const ed = vscode.window.activeTextEditor;
  if (ed && ed.document && ANS_RE.test(path.basename(ed.document.uri.fsPath || ed.document.uri.path))) {
    return ed.document.uri;
  }
  const picked = await vscode.window.showOpenDialog({
    canSelectMany: false,
    openLabel,
  });
  return picked && picked[0] ? picked[0] : null;
}

function listAnsibleFilesInDir(dirPath, maxDepth = 4) {
  const out = [];
  function walk(dir, depth) {
    if (depth > maxDepth) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
    for (const e of entries) {
      if (e.name === 'node_modules' || e.name === '.git') continue;
      const full = path.join(dir, e.name);
      if (e.isFile() && ANS_RE.test(e.name)) out.push(full);
      else if (e.isDirectory() && depth < maxDepth) walk(full, depth + 1);
    }
  }
  walk(dirPath, 0);
  return out.sort();
}

function createTools({ provider, pro, reach }) {
  async function auditPlaybook(uri, opts = {}) {
    if (!(await pro.allowed('auditPlaybook', opts))) return undefined;
    const target = await resolveTargetUri(uri, provider);
    if (!target) return undefined;

    const targetPath = target.fsPath;
    const isDir = target.scheme === 'file' && fs.existsSync(targetPath) && fs.statSync(targetPath).isDirectory();
    const files = isDir ? listAnsibleFilesInDir(targetPath) : [targetPath];
    if (!files.length) {
      vscode.window.showInformationMessage('No Ansible playbook YAML or INI inventory files were found in this folder.');
      return undefined;
    }

    const entries = [];
    for (const f of files) {
      const buf = f === targetPath && target.scheme !== 'file'
        ? Buffer.from(await vscode.workspace.fs.readFile(target))
        : fs.readFileSync(f);
      const label = isDir ? path.relative(targetPath, f) : path.basename(f);
      entries.push({ fileName: label, parsed: parseAnsible(buf, label) });
    }
    const md = buildAuditMarkdown(entries);
    const doc = await vscode.workspace.openTextDocument({ content: md, language: 'markdown' });
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('auditPlaybook');
    if (reach) reach.refresh();
    return { files: files.length, markdown: md };
  }

  async function diffPlaybooks(uri, opts = {}) {
    if (!(await pro.allowed('diffPlaybooks', opts))) return undefined;
    const left = await resolveTargetUri(uri, provider, 'Select baseline Ansible playbook or inventory');
    if (!left) return undefined;

    let right = opts.compareUri || null;
    if (!right) {
      const picked = await vscode.window.showOpenDialog({
        canSelectMany: false,
        openLabel: 'Select second Ansible playbook or inventory to compare',
      });
      right = picked && picked[0] ? picked[0] : null;
    }
    if (!right) return undefined;

    const leftBuf = Buffer.from(await vscode.workspace.fs.readFile(left));
    const rightBuf = Buffer.from(await vscode.workspace.fs.readFile(right));
    const leftName = path.basename(left.fsPath || left.path);
    const rightName = path.basename(right.fsPath || right.path);
    const md = buildDiffMarkdown(
      leftName,
      parseAnsible(leftBuf, leftName),
      rightName,
      parseAnsible(rightBuf, rightName),
    );
    const doc = await vscode.workspace.openTextDocument({ content: md, language: 'markdown' });
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('diffPlaybooks');
    if (reach) reach.refresh();
    return { markdown: md };
  }

  async function exportRunbook(uri, opts = {}) {
    if (!(await pro.allowed('exportRunbook', opts))) return undefined;
    const target = await resolveTargetUri(uri, provider);
    if (!target) return undefined;

    const targetPath = target.fsPath;
    const bytes = await vscode.workspace.fs.readFile(target);
    const baseName = path.basename(targetPath);
    const parsed = parseAnsible(Buffer.from(bytes), baseName);
    const stemRaw = baseName.replace(/[^a-zA-Z0-9._-]+/g, '_') || 'playbook';
    const defaultOut = uniquePath(path.join(path.dirname(targetPath), `${stemRaw}.runbook.md`));
    const saveUri = opts.outPath
      ? vscode.Uri.file(uniquePath(opts.outPath))
      : await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file(defaultOut),
        filters: { 'Markdown Runbook': ['md'] },
        saveLabel: 'Save Ansible task runbook and inventory CSV',
      });
    if (!saveUri) return undefined;

    const mdPath = uniquePath(saveUri.fsPath);
    const dir = path.dirname(mdPath);
    const stem = path.basename(mdPath, '.md').replace(/\.runbook$/i, '');
    const csvPath = uniquePath(path.join(dir, `${stem}.inventory.csv`));

    fs.writeFileSync(mdPath, buildRunbookMarkdown(parsed, baseName), 'utf8');
    fs.writeFileSync(csvPath, buildRunbookCsv(parsed), 'utf8');

    const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(mdPath));
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('exportRunbook');
    if (reach) reach.refresh();
    return { files: [mdPath, csvPath], tasks: parsed.stats.taskCount };
  }

  return { auditPlaybook, diffPlaybooks, exportRunbook };
}

module.exports = { createTools, uniquePath, listAnsibleFilesInDir };
