const token = localStorage.getItem('hydra_token');
if (!token) {
  location.href = '/login.html';
}

let keys = [];

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
    tr.innerHTML = `
      <td class="key-cell">${escapeHtml(k.key)}</td>
      <td>${expLabel}</td>
      <td class="ip-cell">${escapeHtml(k.ip || '') || '<span class="muted">not bound</span>'}</td>
      <td>${escapeHtml(k.note || '')}</td>
      <td>${fmtDate(k.createdAt)}</td>
      <td>
        <div class="cell-actions">
          <button class="btn btn-ghost" data-act="extend" data-key="${escapeAttr(k.key)}">Extend</button>
          <button class="btn btn-ghost" data-act="clearip" data-key="${escapeAttr(k.key)}">Clear IP</button>
          <button class="btn" data-act="del" data-key="${escapeAttr(k.key)}">Delete</button>
        </div>
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
document.querySelectorAll('.dash-tab').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.dash-tab').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-keys').classList.toggle('hidden', btn.dataset.tab !== 'keys');
    document.getElementById('tab-security').classList.toggle('hidden', btn.dataset.tab !== 'security');
  });
});

/* Create panel */
const createPanel = document.getElementById('createKeyPanel');
document.getElementById('newKeyBtn').addEventListener('click', () => createPanel.classList.toggle('hidden'));
document.getElementById('cancelKeyBtn').addEventListener('click', () => createPanel.classList.add('hidden'));

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
  const note = document.getElementById('newNote').value.trim();
  status.className = 'panel-status';
  status.textContent = 'Creating...';

  try {
    await api('/api/keys', {
      method: 'POST',
      body: JSON.stringify({ key, expiration: expiration ? new Date(expiration).toISOString() : null, note }),
    });
    status.className = 'panel-status ok';
    status.textContent = 'Key created.';
    document.getElementById('newKey').value = '';
    document.getElementById('newNote').value = '';
    await loadKeys();
  } catch (err) {
    status.className = 'panel-status err';
    status.textContent = err.message;
  }
});

/* Row actions */
document.getElementById('keysBody').addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-act]');
  if (!btn) return;
  const { act, key } = btn.dataset;

  try {
    if (act === 'del') {
      if (!confirm('Delete key ' + key + '?')) return;
      await api('/api/keys/' + encodeURIComponent(key), { method: 'DELETE' });
    } else if (act === 'extend') {
      const input = prompt('New expiration (YYYY-MM-DDTHH:MM, or leave empty for never):', '');
      if (input === null) return;
      let expiration = null;
      if (input.trim() !== '') {
        const d = new Date(input);
        if (isNaN(d.getTime())) { alert('Invalid date.'); return; }
        expiration = d.toISOString();
      }
      await api('/api/keys/' + encodeURIComponent(key), { method: 'PATCH', body: JSON.stringify({ expiration }) });
    } else if (act === 'clearip') {
      await api('/api/keys/' + encodeURIComponent(key), { method: 'PATCH', body: JSON.stringify({ ip: '' }) });
    }
    await loadKeys();
  } catch (err) {
    alert(err.message);
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

loadKeys().catch((err) => alert(err.message));
