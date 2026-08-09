const token = localStorage.getItem('hydra_token');
if (!token) {
  location.href = '/login.html';
}

let keys = [];
let plans = [];
let subscriptions = [];
let admins = [];
let me = { role: 'admin', permissions: [] };

function can(perm) {
  return me.role === 'owner' || (me.permissions || []).includes(perm);
}

const PERM_GROUPS = [
  {
    label: 'Pages',
    perms: [
      { key: 'tab.keys', label: 'Keys page' },
      { key: 'tab.subscriptions', label: 'Subscriptions page' },
      { key: 'tab.security', label: 'Security page' },
    ],
  },
  {
    label: 'Key actions',
    perms: [
      { key: 'keys.create', label: 'Create key' },
      { key: 'keys.extend', label: 'Extend key' },
      { key: 'keys.clearip', label: 'Clear IP' },
      { key: 'keys.delete', label: 'Delete key' },
    ],
  },
  {
    label: 'Subscription actions',
    perms: [
      { key: 'plans.manage', label: 'Manage plans' },
      { key: 'subs.fulfill', label: 'Mark key given' },
      { key: 'subs.delete', label: 'Delete subscriber' },
    ],
  },
  {
    label: 'Security actions',
    perms: [
      { key: 'security.password', label: 'Change own password' },
      { key: 'security.admins', label: 'Manage admin accounts' },
    ],
  },
];

function api(url, options = {}) {
  return fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer ' + token,
      ...(options.headers || {}),
    },
  }).then(async (res) => {
    const data = await res.json().catch(() => ({}));
    if (res.status === 401) {
      localStorage.removeItem('hydra_token');
      location.href = '/login.html';
      throw new Error('Session expired');
    }
    if (!res.ok) throw new Error(data.error || 'Request failed');
    return data;
  });
}

function fmtDate(value) {
  if (!value) return 'Never';
  const d = new Date(value);
  return isNaN(d.getTime()) ? 'Invalid' : d.toLocaleString();
}

function renderKeys() {
  const body = document.getElementById('keysBody');
  const empty = document.getElementById('keysEmpty');
  body.innerHTML = '';
  empty.style.display = keys.length ? 'none' : 'block';

  keys.forEach((k) => {
    const expired = k.expiration && new Date(k.expiration).getTime() < Date.now();
    const expLabel = expired ? '<span class="badge badge-expired">EXPIRED</span>' : fmtDate(k.expiration);

    const tr = document.createElement('tr');
    const actions = [];
    if (can('keys.extend')) actions.push('<button class="btn btn-ghost" data-act="extend" data-key="' + escapeAttr(k.key) + '">Extend</button>');
    if (can('keys.clearip')) actions.push('<button class="btn btn-ghost" data-act="clearip" data-key="' + escapeAttr(k.key) + '">Clear IP</button>');
    if (can('keys.delete')) actions.push('<button class="btn" data-act="del" data-key="' + escapeAttr(k.key) + '">Delete</button>');
    tr.innerHTML = `
      <td class="key-cell">${escapeHtml(k.key)}</td>
      <td>${expLabel}</td>
      <td class="ip-cell">${escapeHtml(k.ip || '') || '<span class="muted">not bound</span>'}</td>
      <td>${escapeHtml(k.note || '')}</td>
      <td>${fmtDate(k.createdAt)}</td>
      <td>
        <div class="cell-actions">${actions.length ? actions.join('') : '<span class="muted">—</span>'}</div>
      </td>
    `;
    body.appendChild(tr);
  });
}

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function escapeAttr(s) {
  return escapeHtml(s).replace(/'/g, '&#39;');
}

async function loadKeys() {
  const data = await api('/api/keys');
  keys = data.keys;
  renderKeys();
}

/* Filter */
document.getElementById('keyFilter').addEventListener('input', (e) => {
  const q = e.target.value.trim().toLowerCase();
  const rows = document.querySelectorAll('#keysBody tr');
  rows.forEach((tr) => {
    tr.style.display = tr.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
});

/* Tabs */
const tabs = { keys: 'tab-keys', subscriptions: 'tab-subscriptions', security: 'tab-security' };

function switchTo(tab) {
  document.querySelectorAll('.dash-tab').forEach((b) => b.classList.toggle('active', b.dataset.tab === tab));
  Object.entries(tabs).forEach(([t, id]) => {
    document.getElementById(id).classList.toggle('hidden', t !== tab);
  });
  if (tab === 'subscriptions') loadSubscriptions().catch(() => {});
  if (tab === 'security' && can('security.admins')) loadAdmins().catch(() => {});
}

document.querySelectorAll('.dash-tab').forEach((btn) => {
  btn.addEventListener('click', () => switchTo(btn.dataset.tab));
});

function applyPermissions() {
  document.querySelectorAll('.dash-tab').forEach((btn) => {
    btn.style.display = can('tab.' + btn.dataset.tab) ? '' : 'none';
  });
  document.getElementById('newKeyBtn').style.display = can('keys.create') ? '' : 'none';
  document.getElementById('newPlanBtn').style.display = can('plans.manage') ? '' : 'none';
  document.getElementById('passwordPanel').style.display = can('security.password') ? '' : 'none';
  document.getElementById('adminsPanel').style.display = can('security.admins') ? '' : 'none';

  const isOwner = me.role === 'owner';
  document.getElementById('downloadUrl').disabled = !isOwner;
  document.getElementById('saveDownloadBtn').style.display = isOwner ? '' : 'none';

  let active = document.querySelector('.dash-tab.active');
  if (!active || active.style.display === 'none') {
    active = document.querySelector('.dash-tab:not([style*="display: none"])') || document.querySelector('.dash-tab');
  }
  switchTo(active.dataset.tab);
}

/* Create panel */
const createPanel = document.getElementById('createKeyPanel');
document.getElementById('newKeyBtn').addEventListener('click', () => createPanel.classList.toggle('hidden'));
document.getElementById('cancelKeyBtn').addEventListener('click', () => createPanel.classList.add('hidden'));

const newSubscriber = document.getElementById('newSubscriber');
let pendingSubs = [];

async function populateSubscriberSelect() {
  pendingSubs = [];
  newSubscriber.innerHTML = '<option value="">None (manual)</option>';
  if (!can('tab.subscriptions')) return;
  try {
    const data = await api('/api/subscriptions');
    pendingSubs = data.subscriptions.filter((s) => !s.fulfilled);
    pendingSubs.forEach((s) => {
      const opt = document.createElement('option');
      opt.value = s._id;
      opt.textContent = s.discord + ' (' + s.plan + ')';
      newSubscriber.appendChild(opt);
    });
  } catch (e) {
    /* dropdown stays empty */
  }
}

newSubscriber.addEventListener('change', () => {
  const sub = pendingSubs.find((s) => s._id === newSubscriber.value);
  if (sub) document.getElementById('newNote').value = 'Discord: ' + sub.discord;
});

document.getElementById('genKeyBtn').addEventListener('click', () => {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const seg = () => Array.from(crypto.getRandomValues(new Uint8Array(4)))
    .map((b) => chars[b % chars.length]).join('');
  document.getElementById('newKey').value = `HS-${seg()}-${seg()}-${seg()}`;
});

document.getElementById('createKeyBtn').addEventListener('click', async () => {
  const status = document.getElementById('createStatus');
  const key = document.getElementById('newKey').value.trim();
  const expiration = document.getElementById('newExpiration').value;
  let note = document.getElementById('newNote').value.trim();
  const subscriberId = newSubscriber.value;
  status.className = 'panel-status';
  status.textContent = 'Creating...';

  try {
    await api('/api/keys', {
      method: 'POST',
      body: JSON.stringify({ key, expiration: expiration ? new Date(expiration).toISOString() : null, note }),
    });
    if (subscriberId) {
      try {
        await api('/api/subscriptions/' + subscriberId, { method: 'PATCH', body: JSON.stringify({ fulfilled: true }) });
      } catch (e) {
        /* key created but marking subscriber failed */
      }
    }
    status.className = 'panel-status ok';
    status.textContent = 'Key created.';
    document.getElementById('newKey').value = '';
    document.getElementById('newNote').value = '';
    newSubscriber.value = '';
    await loadKeys();
    await populateSubscriberSelect();
  } catch (err) {
    status.className = 'panel-status err';
    status.textContent = err.message;
  }
});

function toLocalInput(value) {
  if (!value) return '';
  const d = new Date(value);
  if (isNaN(d.getTime())) return '';
  const pad = (n) => String(n).padStart(2, '0');
  return (
    d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
    'T' + pad(d.getHours()) + ':' + pad(d.getMinutes())
  );
}

/* Row actions */
const extendPanel = document.getElementById('extendKeyPanel');
let extendingKey = null;

document.getElementById('keysBody').addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-act]');
  if (!btn) return;
  const { act, key } = btn.dataset;

  try {
    if (act === 'del') {
      if (!confirm('Delete key ' + key + '?')) return;
      await api('/api/keys/' + encodeURIComponent(key), { method: 'DELETE' });
    } else if (act === 'extend') {
      const k = keys.find((x) => x.key === key);
      document.getElementById('extendExpiration').value = k ? toLocalInput(k.expiration) : '';
      document.getElementById('extendStatus').className = 'panel-status';
      document.getElementById('extendStatus').textContent = '';
      extendingKey = key;
      extendPanel.classList.remove('hidden');
      extendPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } else if (act === 'clearip') {
      await api('/api/keys/' + encodeURIComponent(key), { method: 'PATCH', body: JSON.stringify({ ip: '' }) });
      await loadKeys();
    }
  } catch (err) {
    alert(err.message);
  }
});

document.getElementById('extendCancelBtn').addEventListener('click', () => {
  extendPanel.classList.add('hidden');
  extendingKey = null;
});

document.getElementById('extendSaveBtn').addEventListener('click', async () => {
  const status = document.getElementById('extendStatus');
  const val = document.getElementById('extendExpiration').value;
  let expiration = null;

  if (val.trim() !== '') {
    const d = new Date(val);
    if (isNaN(d.getTime())) {
      status.className = 'panel-status err';
      status.textContent = 'Invalid date.';
      return;
    }
    expiration = d.toISOString();
  }

  status.className = 'panel-status';
  status.textContent = 'Saving...';
  try {
    await api('/api/keys/' + encodeURIComponent(extendingKey), { method: 'PATCH', body: JSON.stringify({ expiration }) });
    extendPanel.classList.add('hidden');
    extendingKey = null;
    await loadKeys();
  } catch (err) {
    status.className = 'panel-status err';
    status.textContent = err.message;
  }
});

/* Subscriptions */
function renderPlans() {
  const body = document.getElementById('plansBody');
  const empty = document.getElementById('plansEmpty');
  body.innerHTML = '';
  empty.style.display = plans.length ? 'none' : 'block';

  plans.forEach((p) => {
    const tr = document.createElement('tr');
    const dur = p.duration > 0 ? p.duration + ' day' + (p.duration === 1 ? '' : 's') : '<span class="muted">n/a</span>';
    const status = p.active
      ? '<span class="badge badge-ok">ACTIVE</span>'
      : '<span class="badge">HIDDEN</span>';
    const manageActions = can('plans.manage')
      ? `<button class="btn btn-ghost" data-plan-act="toggle" data-plan-id="${p._id}" data-plan-active="${p.active}">${p.active ? 'Hide' : 'Show'}</button>
         <button class="btn btn-ghost" data-plan-act="edit" data-plan-id="${p._id}">Edit</button>
         <button class="btn" data-plan-act="del" data-plan-id="${p._id}" data-plan-name="${escapeAttr(p.name)}">Delete</button>`
      : '<span class="muted">—</span>';
    tr.innerHTML = `
      <td class="key-cell">${escapeHtml(p.name)}</td>
      <td>${escapeHtml(p.price || '—')}</td>
      <td>${dur}</td>
      <td>${status}</td>
      <td>${fmtDate(p.createdAt)}</td>
      <td>
        <div class="cell-actions">${manageActions}</div>
      </td>
    `;
    body.appendChild(tr);
  });
}

function renderSubs() {
  const body = document.getElementById('subsBody');
  const empty = document.getElementById('subsEmpty');
  body.innerHTML = '';
  empty.style.display = subscriptions.length ? 'none' : 'block';

  subscriptions.forEach((s) => {
    const tr = document.createElement('tr');
    const status = s.fulfilled
      ? '<span class="badge badge-ok">KEY GIVEN</span>'
      : '<span class="badge badge-expired">PENDING</span>';
    tr.innerHTML = `
      <td class="key-cell">${escapeHtml(s.requestId || '—')}</td>
      <td class="ip-cell">${escapeHtml(s.discord)}</td>
      <td>${escapeHtml(s.plan)}</td>
      <td>${escapeHtml(s.note || '')}</td>
      <td>${fmtDate(s.createdAt)}</td>
      <td>${status}</td>
      <td>
        <div class="cell-actions">${renderSubActions(s)}</div>
      </td>
    `;
    body.appendChild(tr);
  });
}

function renderSubActions(s) {
  const btns = [];
  if (can('subs.fulfill')) {
    btns.push(`<button class="btn btn-ghost" data-sub-act="fulfill" data-sub-id="${s._id}" data-sub-fulfilled="${s.fulfilled}">${s.fulfilled ? 'Unmark' : 'Key Given'}</button>`);
  }
  if (can('subs.delete')) {
    btns.push(`<button class="btn" data-sub-act="del" data-sub-id="${s._id}" data-sub-name="${escapeAttr(s.discord)}">Delete</button>`);
  }
  return btns.length ? btns.join('') : '<span class="muted">—</span>';
}

async function loadSubscriptions() {
  const [planData, subData] = await Promise.all([api('/api/plans'), api('/api/subscriptions')]);
  plans = planData.plans;
  subscriptions = subData.subscriptions;
  renderPlans();
  renderSubs();
}

/* Plan create panel */
const planPanel = document.getElementById('createPlanPanel');
document.getElementById('newPlanBtn').addEventListener('click', () => planPanel.classList.toggle('hidden'));
document.getElementById('cancelPlanBtn').addEventListener('click', () => planPanel.classList.add('hidden'));

document.getElementById('createPlanBtn').addEventListener('click', async () => {
  const status = document.getElementById('planStatus');
  const name = document.getElementById('planName').value.trim();
  const price = document.getElementById('planPrice').value.trim();
  const duration = Number(document.getElementById('planDuration').value);
  const description = document.getElementById('planDescription').value.trim();
  const active = document.getElementById('planActive').value === 'true';
  status.className = 'panel-status';
  status.textContent = 'Creating...';

  try {
    await api('/api/plans', {
      method: 'POST',
      body: JSON.stringify({ name, price, duration, description, active }),
    });
    status.className = 'panel-status ok';
    status.textContent = 'Plan created.';
    document.getElementById('planName').value = '';
    document.getElementById('planPrice').value = '';
    document.getElementById('planDuration').value = '';
    document.getElementById('planDescription').value = '';
    await loadSubscriptions();
  } catch (err) {
    status.className = 'panel-status err';
    status.textContent = err.message;
  }
});

/* Plans table actions */
const editPlanPanel = document.getElementById('editPlanPanel');
let editingPlanId = null;

document.getElementById('plansBody').addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-plan-act]');
  if (!btn) return;
  const { planAct: act, planId } = btn.dataset;

  try {
    if (act === 'del') {
      if (!confirm('Delete plan "' + btn.dataset.planName + '"?')) return;
      await api('/api/plans/' + planId, { method: 'DELETE' });
    } else if (act === 'toggle') {
      await api('/api/plans/' + planId, { method: 'PATCH', body: JSON.stringify({ active: btn.dataset.planActive !== 'true' }) });
    } else if (act === 'edit') {
      const plan = plans.find((p) => p._id === planId);
      if (!plan) return;
      editingPlanId = planId;
      document.getElementById('editPlanName').value = plan.name;
      document.getElementById('editPlanPrice').value = plan.price || '';
      document.getElementById('editPlanDuration').value = plan.duration || '';
      document.getElementById('editPlanActive').value = String(plan.active);
      document.getElementById('editPlanDescription').value = plan.description || '';
      document.getElementById('editPlanStatus').className = 'panel-status';
      document.getElementById('editPlanStatus').textContent = '';
      editPlanPanel.classList.remove('hidden');
      editPlanPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    await loadSubscriptions();
  } catch (err) {
    alert(err.message);
  }
});

document.getElementById('cancelEditPlanBtn').addEventListener('click', () => {
  editPlanPanel.classList.add('hidden');
  editingPlanId = null;
});

document.getElementById('savePlanBtn').addEventListener('click', async () => {
  const status = document.getElementById('editPlanStatus');
  const name = document.getElementById('editPlanName').value.trim();
  const price = document.getElementById('editPlanPrice').value.trim();
  const duration = Number(document.getElementById('editPlanDuration').value);
  const active = document.getElementById('editPlanActive').value === 'true';
  const description = document.getElementById('editPlanDescription').value.trim();
  status.className = 'panel-status';
  status.textContent = 'Saving...';

  try {
    await api('/api/plans/' + editingPlanId, {
      method: 'PATCH',
      body: JSON.stringify({ name, price, duration, active, description }),
    });
    status.className = 'panel-status ok';
    status.textContent = 'Saved.';
    editPlanPanel.classList.add('hidden');
    editingPlanId = null;
    await loadSubscriptions();
  } catch (err) {
    status.className = 'panel-status err';
    status.textContent = err.message;
  }
});

/* Subscribers table actions */
document.getElementById('subsBody').addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-sub-act]');
  if (!btn) return;
  const { subAct: act, subId } = btn.dataset;

  try {
    if (act === 'del') {
      if (!confirm('Delete subscription for ' + btn.dataset.subName + '?')) return;
      await api('/api/subscriptions/' + subId, { method: 'DELETE' });
    } else if (act === 'fulfill') {
      await api('/api/subscriptions/' + subId, { method: 'PATCH', body: JSON.stringify({ fulfilled: btn.dataset.subFulfilled !== 'true' }) });
    }
    await loadSubscriptions();
  } catch (err) {
    alert(err.message);
  }
});

/* Admin accounts */
const createAdminPanel = document.getElementById('createAdminPanel');
const editAdminPanel = document.getElementById('editAdminPanel');
let editingAdminName = null;

function buildPermCheckboxes(container, selected) {
  container.innerHTML = '';
  PERM_GROUPS.forEach((g) => {
    const group = document.createElement('div');
    group.className = 'perm-group';
    const title = document.createElement('h4');
    title.textContent = g.label;
    group.appendChild(title);
    g.perms.forEach((p) => {
      const label = document.createElement('label');
      label.className = 'perm-check';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.value = p.key;
      cb.checked = (selected || []).includes(p.key);
      label.appendChild(cb);
      label.appendChild(document.createTextNode(p.label));
      group.appendChild(label);
    });
    container.appendChild(group);
  });
}

function renderAdmins() {
  const body = document.getElementById('adminsBody');
  const empty = document.getElementById('adminsEmpty');
  body.innerHTML = '';
  empty.style.display = admins.length ? 'none' : 'block';

  admins.forEach((a) => {
    const isOwner = a.role === 'owner';
    const perms = a.permissions || [];
    const permsLabel = isOwner ? 'All access' : (perms.length ? escapeHtml(perms.join(', ')) : '<span class="muted">None</span>');
    const rowActions = isOwner
      ? '<span class="muted">—</span>'
      : `<button class="btn btn-ghost" data-admin-act="edit" data-admin-username="${escapeAttr(a.username)}">Edit</button>
         <button class="btn" data-admin-act="del" data-admin-username="${escapeAttr(a.username)}">Delete</button>`;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="key-cell">${escapeHtml(a.username)}</td>
      <td>${isOwner ? '<span class="badge badge-ok">OWNER</span>' : '<span class="badge">ADMIN</span>'}</td>
      <td>${permsLabel}</td>
      <td>${fmtDate(a.createdAt)}</td>
      <td><div class="cell-actions">${rowActions}</div></td>
    `;
    body.appendChild(tr);
  });
}

async function loadAdmins() {
  const data = await api('/api/admins');
  admins = data.admins;
  renderAdmins();
}

buildPermCheckboxes(document.getElementById('createAdminPerms'), []);
document.getElementById('newAdminBtn').addEventListener('click', () => createAdminPanel.classList.toggle('hidden'));
document.getElementById('cancelCreateAdminBtn').addEventListener('click', () => createAdminPanel.classList.add('hidden'));

document.getElementById('createAdminBtn').addEventListener('click', async () => {
  const status = document.getElementById('createAdminStatus');
  const username = document.getElementById('adminUsername').value.trim();
  const password = document.getElementById('adminPassword').value;
  const permissions = Array.from(document.querySelectorAll('#createAdminPerms input:checked')).map((cb) => cb.value);
  status.className = 'panel-status';
  status.textContent = 'Creating...';

  try {
    await api('/api/admins', { method: 'POST', body: JSON.stringify({ username, password, permissions }) });
    status.className = 'panel-status ok';
    status.textContent = 'Admin created.';
    document.getElementById('adminUsername').value = '';
    document.getElementById('adminPassword').value = '';
    document.querySelectorAll('#createAdminPerms input').forEach((cb) => (cb.checked = false));
    await loadAdmins();
  } catch (err) {
    status.className = 'panel-status err';
    status.textContent = err.message;
  }
});

document.getElementById('adminsBody').addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-admin-act]');
  if (!btn) return;
  const { adminAct: act, adminUsername } = btn.dataset;

  try {
    if (act === 'del') {
      if (!confirm('Delete admin "' + adminUsername + '"?')) return;
      await api('/api/admins/' + encodeURIComponent(adminUsername), { method: 'DELETE' });
      await loadAdmins();
    } else if (act === 'edit') {
      const admin = admins.find((a) => a.username === adminUsername);
      if (!admin) return;
      editingAdminName = adminUsername;
      document.getElementById('editAdminName').textContent = adminUsername;
      document.getElementById('editAdminPassword').value = '';
      document.getElementById('editAdminStatus').className = 'panel-status';
      document.getElementById('editAdminStatus').textContent = '';
      buildPermCheckboxes(document.getElementById('editAdminPerms'), admin.permissions);
      editAdminPanel.classList.remove('hidden');
      editAdminPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  } catch (err) {
    alert(err.message);
  }
});

document.getElementById('cancelEditAdminBtn').addEventListener('click', () => {
  editAdminPanel.classList.add('hidden');
  editingAdminName = null;
});

document.getElementById('saveAdminBtn').addEventListener('click', async () => {
  const status = document.getElementById('editAdminStatus');
  const password = document.getElementById('editAdminPassword').value;
  const permissions = Array.from(document.querySelectorAll('#editAdminPerms input:checked')).map((cb) => cb.value);
  status.className = 'panel-status';
  status.textContent = 'Saving...';

  const body = { permissions };
  if (password.trim() !== '') body.password = password;

  try {
    await api('/api/admins/' + encodeURIComponent(editingAdminName), { method: 'PATCH', body: JSON.stringify(body) });
    status.className = 'panel-status ok';
    status.textContent = 'Saved.';
    editAdminPanel.classList.add('hidden');
    editingAdminName = null;
    await loadAdmins();
  } catch (err) {
    status.className = 'panel-status err';
    status.textContent = err.message;
  }
});

/* Download link setting */
async function loadDownloadSetting() {
  try {
    const data = await api('/api/settings/download');
    document.getElementById('downloadUrl').value = data.url || '';
  } catch (e) {
    /* ignore */
  }
}

document.getElementById('saveDownloadBtn').addEventListener('click', async () => {
  const status = document.getElementById('downloadStatus');
  status.className = 'panel-status';
  status.textContent = 'Saving...';
  try {
    await api('/api/settings/download', {
      method: 'PATCH',
      body: JSON.stringify({ url: document.getElementById('downloadUrl').value }),
    });
    status.className = 'panel-status ok';
    status.textContent = 'Link saved.';
  } catch (err) {
    status.className = 'panel-status err';
    status.textContent = err.message;
  }
});

/* Password */
document.getElementById('passwordForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const status = document.getElementById('passwordStatus');
  status.className = 'form-error';
  status.textContent = '';

  try {
    await api('/api/password', {
      method: 'POST',
      body: JSON.stringify({
        current: document.getElementById('curPassword').value,
        next: document.getElementById('newPassword').value,
      }),
    });
    status.textContent = 'Password updated.';
    status.style.color = '#7ed17e';
    document.getElementById('curPassword').value = '';
    document.getElementById('newPassword').value = '';
  } catch (err) {
    status.textContent = err.message;
    status.style.color = '#ff6b60';
  }
});

/* Logout */
document.getElementById('logoutBtn').addEventListener('click', async () => {
  try { await api('/api/logout', { method: 'POST' }); } catch (e) {}
  localStorage.removeItem('hydra_token');
  location.href = '/';
});

async function init() {
  try {
    me = await api('/api/me');
  } catch (e) {
    return;
  }
  applyPermissions();
  if (can('tab.keys')) loadKeys().catch((err) => alert(err.message));
  if (can('security.admins')) loadAdmins().catch(() => {});
  if (can('tab.security')) loadDownloadSetting().catch(() => {});
  populateSubscriberSelect().catch(() => {});
}

init();
