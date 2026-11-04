'use strict';
const STORAGE_KEY = 'amp-vault-v1';
const VERIFIER_TEXT = 'amp-verifier';
const ITERATIONS = 210000;
const LOCK_MS = 5 * 60 * 1000;

let vault = null; // {salt, verifier, accounts: []}
let key = null;
let currentId = null;
let currentPlainPassword = null;
let lockTimer = null;

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();
const b64e = (buf) => { let s = ''; const b = new Uint8Array(buf); for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); };
const b64d = (s) => { const bin = atob(s); const b = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i); return b.buffer; };

function loadVault() { try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null'); } catch { return null; } }
function saveVault() { localStorage.setItem(STORAGE_KEY, JSON.stringify(vault)); }
function showError(id, msg) { const el = $(id); el.textContent = msg; el.hidden = !msg; }
function strengthOf(pw) {
  if (!pw) return '';
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return ['很弱', '弱', '一般', '较强', '强', '很强'][score] || '';
}
async function deriveKey(password, saltB64) {
  if (!window.crypto || !window.crypto.subtle) throw new Error('当前浏览器环境没有提供 Web Crypto 加密接口，请用 https 或 http://localhost 打开本页。');
  const salt = b64d(saltB64);
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encryptText(k, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, enc.encode(text));
  const out = new Uint8Array(iv.length + ct.byteLength);
  out.set(iv, 0); out.set(new Uint8Array(ct), iv.length);
  return b64e(out.buffer);
}
async function decryptText(k, data) {
  const buf = new Uint8Array(b64d(data));
  const iv = buf.slice(0, 12); const ct = buf.slice(12);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, k, ct);
  return dec.decode(pt);
}
function resetLockTimer() {
  if (!key) return;
  clearTimeout(lockTimer);
  lockTimer = setTimeout(lock, LOCK_MS);
}
function lock() {
  key = null; vault = loadVault(); currentId = null; currentPlainPassword = null;
  $('vaultScreen').hidden = true; $('changePassCard').hidden = true; $('importCard').hidden = true;
  $('lockScreen').hidden = false;
  renderLock();
}
function renderLock() {
  const v = loadVault();
  if (!v) {
    $('lockTitle').textContent = '设置主密码';
    $('lockHint').textContent = '第一次使用请设置主密码。主密码忘了无法恢复，里面的账号也找不回来，请务必记住。';
    $('confirmWrap').hidden = false;
    $('unlockBtn').textContent = '创建并解锁';
    $('resetBtn').hidden = true;
  } else {
    $('lockTitle').textContent = '输入主密码解锁';
    $('lockHint').textContent = '输入主密码后才能查看账号。5 分钟无操作会自动锁定。';
    $('confirmWrap').hidden = true;
    $('unlockBtn').textContent = '解锁';
    $('resetBtn').hidden = false;
  }
  $('masterPassword').value = ''; $('confirmPassword').value = ''; $('masterStrength').textContent = '';
  showError('lockError', '');
}
async function unlock() {
  const pw = $('masterPassword').value;
  if (!pw) return showError('lockError', '请输入主密码。');
  try {
    const v = loadVault();
    if (!v) {
      const pw2 = $('confirmPassword').value;
      if (pw !== pw2) return showError('lockError', '两次输入的主密码不一致。');
      if (pw.length < 8) return showError('lockError', '主密码至少 8 位。');
      const salt = b64e(crypto.getRandomValues(new Uint8Array(16)).buffer);
      const k = await deriveKey(pw, salt);
      const verifier = await encryptText(k, VERIFIER_TEXT);
      vault = { salt, verifier, accounts: [] };
      saveVault(); key = k;
    } else {
      const k = await deriveKey(pw, v.salt);
      const ok = await decryptText(k, v.verifier).then(t => t === VERIFIER_TEXT).catch(() => false);
      if (!ok) return showError('lockError', '主密码不正确。');
      vault = v; key = k;
    }
    $('lockScreen').hidden = true; $('vaultScreen').hidden = false; $('topActions').hidden = false;
    showError('lockError', '');
    renderList(); resetLockTimer();
  } catch (e) { showError('lockError', e.message || String(e)); }
}
function filteredAccounts() {
  const q = ($('searchInput').value || '').toLowerCase();
  const cat = $('categoryFilter').value;
  const fav = $('favOnly').checked;
  return (vault.accounts || []).filter(a => {
    if (cat && a.category !== cat) return false;
    if (fav && !a.favorite) return false;
    if (!q) return true;
    return [a.name, a.username, a.url, a.notes, a.category].join(' ').toLowerCase().includes(q);
  }).sort((a, b) => a.name.localeCompare(b.name, 'zh-CN'));
}
async function copyPasswordById(id, btn) {
  try {
    const a = vault.accounts.find(x => x.id === id); if (!a) return false;
    const pw = currentPlainPassword && currentId === id ? currentPlainPassword : await decryptText(key, a.passwordEnc);
    try { await navigator.clipboard.writeText(pw); }
    catch (e) {
      const ta = document.createElement('textarea'); ta.value = pw; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      const ok = document.execCommand('copy'); document.body.removeChild(ta);
      if (!ok) throw e;
    }
    if (btn) { const old = btn.textContent; btn.textContent = '已复制'; setTimeout(() => { btn.textContent = old; }, 1500); }
    resetLockTimer();
    return true;
  } catch (e) { alert('复制失败：' + (e.message || String(e)) + '。请确认是在 https 或 http://localhost 下打开本页。'); return false; }
}
function renderList() {
  const cats = [...new Set((vault.accounts || []).map(a => a.category).filter(Boolean))].sort();
  const sel = $('categoryFilter'); const cur = sel.value;
  sel.innerHTML = '<option value="">全部分类</option>' + cats.map(c => `<option>${c.replace(/</g, '&lt;')}</option>`).join('');
  sel.value = cur;
  const list = filteredAccounts();
  $('emptyMsg').hidden = list.length !== 0 || (vault.accounts || []).length !== 0;
  if ((vault.accounts || []).length === 0) $('emptyMsg').textContent = '还没有账号，点“添加账号”开始添加。';
  else if (list.length === 0) $('emptyMsg').textContent = '没有符合条件的账号。';
  const ul = $('accountList'); ul.innerHTML = '';
  list.forEach(a => {
    const li = document.createElement('li');
    const star = a.favorite ? ' ★' : '';
    // 同一平台多个账号时，列表主标题就带上用户名，避免只看名称分不清。
    li.innerHTML = `<div><strong></strong><div class="meta"></div></div><div class="row"><button type="button">复制密码</button><span>›</span></div>`;
    li.querySelector('strong').textContent = (a.username ? a.name + ' · ' + a.username : a.name) + star;
    li.querySelector('.meta').textContent = [a.category, a.url].filter(Boolean).join(' · ') || '—';
    li.querySelector('button').addEventListener('click', (e) => { e.stopPropagation(); copyPasswordById(a.id, e.currentTarget); });
    li.addEventListener('click', () => showDetail(a.id));
    ul.appendChild(li);
  });
}
function parseCSV(text) {
  const rows = []; let row = []; let cur = ''; let inQuotes = false;
  const t = text.replace(/^\uFEFF/, '');
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (inQuotes) {
      if (c === '"') { if (t[i + 1] === '"') { cur += '"'; i++; } else inQuotes = false; }
      else cur += c;
    } else if (c === '"') inQuotes = true;
    else if (c === ',') { row.push(cur); cur = ''; }
    else if (c === '\n') { row.push(cur); rows.push(row); row = []; cur = ''; }
    else if (c !== '\r') cur += c;
  }
  if (cur !== '' || row.length) { row.push(cur); rows.push(row); }
  const clean = rows.filter(r => r.some(v => String(v || '').trim() !== ''));
  if (!clean.length) return [];
  const header = clean[0].map(h => String(h || '').trim().toLowerCase());
  const mapKey = (h) => ({ note: 'notes', website: 'url', site: 'url' }[h] || h);
  return clean.slice(1).map((r, idx) => {
    const o = { _row: idx + 2 };
    header.forEach((h, i) => { o[mapKey(h)] = (r[i] || '').trim(); });
    return o;
  });
}
function parseImportText(text) {
  const t = text.trim();
  if (!t) return [];
  if (t.startsWith('[') || t.startsWith('{')) {
    const data = JSON.parse(t);
    const arr = Array.isArray(data) ? data : (Array.isArray(data.accounts) ? data.accounts : null);
    if (!arr) throw new Error('JSON 格式不对：需要是一个数组，或含 accounts 数组的对象。');
    return arr.map((o, i) => ({ ...o, _row: i + 1 }));
  }
  return parseCSV(t);
}
async function doImport() {
  const file = $('importFile').files[0];
  if (!file) return showError('importError', '请先选择一个 JSON 或 CSV 文件。');
  showError('importError', '');
  $('importResult').textContent = '正在导入…';
  try {
    const text = await file.text();
    const rows = parseImportText(text);
    if (!rows.length) throw new Error('文件里没有可导入的数据行。');
    const seen = new Set((vault.accounts || []).map(a => (a.name + '\0' + (a.username || '')).toLowerCase()));
    let imported = 0, skipped = 0; const failures = [];
    for (const r of rows) {
      const name = String(r.name || '').trim();
      const password = String(r.password || '');
      if (!name || !password) { failures.push(`第 ${r._row} 行：缺少名称或密码`); continue; }
      const k = (name + '\0' + String(r.username || '').trim()).toLowerCase();
      if (seen.has(k)) { skipped++; continue; }
      seen.add(k);
      const passwordEnc = await encryptText(key, password);
      vault.accounts.push({ id: 'a' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7) + imported, name, category: String(r.category || '').trim(), username: String(r.username || '').trim(), url: String(r.url || '').trim(), notes: String(r.notes || '').trim(), favorite: !!r.favorite, passwordEnc, createdAt: Date.now(), updatedAt: Date.now() });
      imported++;
    }
    saveVault(); renderList(); resetLockTimer();
    $('importResult').textContent = `导入完成：成功 ${imported} 条，跳过重复 ${skipped} 条，失败 ${failures.length} 条。` + (failures.length ? '失败明细：' + failures.slice(0, 20).join('；') : '') + ' 请删除刚才的明文导入文件。';
    $('importFile').value = '';
  } catch (e) { showError('importError', e.message || String(e)); $('importResult').textContent = ''; }
}
async function showDetail(id) {
  const a = vault.accounts.find(x => x.id === id); if (!a) return;
  currentId = id; currentPlainPassword = null;
  $('detailName').textContent = a.name;
  $('detailCategory').textContent = a.category || '—';
  $('detailUsername').textContent = a.username || '—';
  $('detailPassword').textContent = '••••••••';
  $('detailToggleBtn').textContent = '显示';
  $('detailUrl').textContent = a.url || '—';
  $('detailNotes').textContent = a.notes || '—';
  $('detailCard').hidden = false;
  $('formCard').hidden = true;
}
function openForm(a) {
  $('formTitle').textContent = a ? '编辑账号' : '添加账号';
  $('editId').value = a ? a.id : '';
  $('fName').value = a ? a.name : '';
  $('fCategory').value = a ? a.category : '';
  $('fUsername').value = a ? a.username : '';
  $('fUrl').value = a ? a.url : '';
  $('fPassword').value = ''; $('fPassword').dataset.keep = a ? '1' : '';
  $('fNotes').value = a ? a.notes : '';
  $('fFavorite').checked = a ? !!a.favorite : false;
  $('formStrength').textContent = '';
  showError('formError', '');
  $('formCard').hidden = false;
}
async function saveForm() {
  const name = $('fName').value.trim();
  const pwInput = $('fPassword').value;
  const id = $('editId').value;
  if (!name) return showError('formError', '请填写名称。');
  if (!id && !pwInput) return showError('formError', '请填写密码，或点生成。');
  try {
    const passwordEnc = pwInput ? await encryptText(key, pwInput) : vault.accounts.find(a => a.id === id).passwordEnc;
    const rec = { id: id || ('a' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7)), name, category: $('fCategory').value.trim(), username: $('fUsername').value.trim(), url: $('fUrl').value.trim(), notes: $('fNotes').value.trim(), favorite: $('fFavorite').checked, passwordEnc, updatedAt: Date.now() };
    if (id) { const i = vault.accounts.findIndex(a => a.id === id); vault.accounts[i] = { ...vault.accounts[i], ...rec }; }
    else { rec.createdAt = Date.now(); vault.accounts.push(rec); }
    saveVault(); $('formCard').hidden = true; renderList(); resetLockTimer();
  } catch (e) { showError('formError', e.message || String(e)); }
}
function genPassword() {
  const len = Math.max(8, Math.min(32, parseInt($('genLength').value || '16', 10)));
  const sets = [];
  if ($('genUpper').checked) sets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  if ($('genLower').checked) sets.push('abcdefghijklmnopqrstuvwxyz');
  if ($('genDigits').checked) sets.push('0123456789');
  if ($('genSymbols').checked) sets.push('!@#$%^&*()-_=+[]{};:,.<>?');
  if (!sets.length) { alert('请至少选一种字符类型。'); return; }
  const all = sets.join('');
  const rnd = crypto.getRandomValues(new Uint32Array(len));
  let out = '';
  for (let i = 0; i < len; i++) out += all[rnd[i] % all.length];
  $('fPassword').value = out; $('formStrength').textContent = '强度：' + strengthOf(out);
}
document.addEventListener('DOMContentLoaded', () => {
  vault = loadVault(); renderLock();
  $('masterPassword').addEventListener('input', e => { $('masterStrength').textContent = e.target.value ? '强度：' + strengthOf(e.target.value) : ''; });
  $('unlockBtn').addEventListener('click', unlock);
  $('masterPassword').addEventListener('keydown', e => { if (e.key === 'Enter') unlock(); });
  $('resetBtn').addEventListener('click', () => { if (confirm('确定要清空整个保险库吗？所有账号都会被删除，无法恢复。')) { localStorage.removeItem(STORAGE_KEY); vault = null; key = null; renderLock(); } });
  $('lockBtn').addEventListener('click', lock);
  $('addBtn').addEventListener('click', () => { openForm(null); $('detailCard').hidden = true; });
  $('cancelBtn').addEventListener('click', () => { $('formCard').hidden = true; });
  $('saveBtn').addEventListener('click', saveForm);
  $('togglePassBtn').addEventListener('click', () => { const el = $('fPassword'); el.type = el.type === 'password' ? 'text' : 'password'; $('togglePassBtn').textContent = el.type === 'password' ? '显示' : '隐藏'; });
  $('genPassBtn').addEventListener('click', genPassword);
  $('fPassword').addEventListener('input', e => { $('formStrength').textContent = e.target.value ? '强度：' + strengthOf(e.target.value) : ''; });
  $('searchInput').addEventListener('input', renderList);
  $('categoryFilter').addEventListener('change', renderList);
  $('favOnly').addEventListener('change', renderList);
  $('detailCloseBtn').addEventListener('click', () => { $('detailCard').hidden = true; });
  $('detailEditBtn').addEventListener('click', () => { const a = vault.accounts.find(x => x.id === currentId); openForm(a); $('detailCard').hidden = true; });
  $('detailDeleteBtn').addEventListener('click', () => { if (!confirm('确定要删除这个账号吗？')) return; vault.accounts = vault.accounts.filter(a => a.id !== currentId); saveVault(); $('detailCard').hidden = true; renderList(); });
  $('detailToggleBtn').addEventListener('click', async () => {
    try {
      if (currentPlainPassword) { $('detailPassword').textContent = '••••••••'; $('detailToggleBtn').textContent = '显示'; currentPlainPassword = null; }
      else { const a = vault.accounts.find(x => x.id === currentId); currentPlainPassword = await decryptText(key, a.passwordEnc); $('detailPassword').textContent = currentPlainPassword; $('detailToggleBtn').textContent = '隐藏'; }
    } catch (e) { alert(e.message || String(e)); }
  });
  $('detailCopyBtn').addEventListener('click', async (e) => { await copyPasswordById(currentId, e.currentTarget); });
  $('importBtn').addEventListener('click', () => { $('importCard').hidden = false; $('formCard').hidden = true; $('detailCard').hidden = true; $('importResult').textContent = ''; showError('importError', ''); $('importFile').value = ''; });
  $('cancelImportBtn').addEventListener('click', () => { $('importCard').hidden = true; });
  $('downloadTemplateBtn').addEventListener('click', () => {
    const csv = 'name,category,username,password,url,notes\n示例平台,社交,示例账号,请替换成真实密码,https://example.com,这是模板里的示例行，导入前请改成你自己的账号\n';
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' });
    const aEl = document.createElement('a'); aEl.href = URL.createObjectURL(blob); aEl.download = 'accounts-import-template.csv'; aEl.click(); URL.revokeObjectURL(aEl.href);
  });
  $('doImportBtn').addEventListener('click', doImport);
  $('exportBtn').addEventListener('click', async () => {
    try {
      const out = [];
      for (const a of vault.accounts) out.push({ name: a.name, category: a.category, username: a.username, password: await decryptText(key, a.passwordEnc), url: a.url, notes: a.notes, favorite: a.favorite });
      const blob = new Blob([JSON.stringify(out, null, 2)], { type: 'application/json' });
      const aEl = document.createElement('a'); aEl.href = URL.createObjectURL(blob); aEl.download = 'accounts-export.json'; aEl.click(); URL.revokeObjectURL(aEl.href);
    } catch (e) { alert(e.message || String(e)); }
  });
  $('changePassBtn').addEventListener('click', () => { $('changePassCard').hidden = false; });
  $('cancelChangeBtn').addEventListener('click', () => { $('changePassCard').hidden = true; });
  $('doChangeBtn').addEventListener('click', async () => {
    const oldPw = $('oldPassword').value, newPw = $('newPassword').value, newPw2 = $('newPassword2').value;
    if (newPw !== newPw2) return showError('changeError', '两次新主密码不一致。');
    if (newPw.length < 8) return showError('changeError', '新主密码至少 8 位。');
    try {
      const oldKey = await deriveKey(oldPw, vault.salt);
      const ok = await decryptText(oldKey, vault.verifier).then(t => t === VERIFIER_TEXT).catch(() => false);
      if (!ok) return showError('changeError', '当前主密码不正确。');
      const plains = [];
      for (const a of vault.accounts) plains.push(await decryptText(oldKey, a.passwordEnc));
      const salt = b64e(crypto.getRandomValues(new Uint8Array(16)).buffer);
      const newKey = await deriveKey(newPw, salt);
      const verifier = await encryptText(newKey, VERIFIER_TEXT);
      for (let i = 0; i < vault.accounts.length; i++) vault.accounts[i].passwordEnc = await encryptText(newKey, plains[i]);
      vault.salt = salt; vault.verifier = verifier; key = newKey; saveVault();
      $('changePassCard').hidden = true; $('oldPassword').value = ''; $('newPassword').value = ''; $('newPassword2').value = ''; showError('changeError', ''); alert('主密码已修改，旧主密码已失效。'); resetLockTimer();
    } catch (e) { showError('changeError', e.message || String(e)); }
  });
  ['click', 'keydown'].forEach(ev => document.addEventListener(ev, resetLockTimer, true));
});
