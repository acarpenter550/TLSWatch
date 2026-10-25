/* TLS Watch — dependency-free dashboard client. All server text is inserted via textContent. */
const $ = (id) => document.getElementById(id);
const state = { sites: [], groups: [], agents: [], activeGroup: 'all', timezone: '', loading: true, toastTimer: null };

const icons = {
  globe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c-6 5-6 13 0 18M12 3c6 5 6 13 0 18"/></svg>',
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>',
  refresh: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 7v5h-5M4 17v-5h5"/><path d="M5 9a8 8 0 0 1 14-2l1 5M4 12l1 5a8 8 0 0 0 14-2"/></svg>',
  pause: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M8 5v14M16 5v14"/></svg>',
  play: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"><path d="m7 4 14 8-14 8z"/></svg>',
  groups: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="8" height="7" rx="1"/><rect x="13" y="4" width="8" height="7" rx="1"/><rect x="3" y="13" width="8" height="7" rx="1"/><rect x="13" y="13" width="8" height="7" rx="1"/></svg>',
  history: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M3 3v6h6M3 9a9 9 0 1 1 2 8M12 7v5l4 2"/></svg>',
  certificate: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2.5" width="14" height="19" rx="2"/><path d="M9 7h6M9 11h6M9 15h4"/></svg>',
  trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M8 6V4h8v2M6 6l1 15h10l1-15M10 10v7M14 10v7"/></svg>'
};

function element(tag, className = '', text = '') {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined && text !== null) el.textContent = String(text);
  return el;
}
function add(parent, ...children) { children.forEach(c => parent.appendChild(c)); return parent; }
function shortHost(site) { return site.hostname + (site.port !== 443 ? `:${site.port}` : ''); }
function dateParts(iso) {
  if (!iso) return { date: '—', time: '—' };
  const value = new Date(iso);
  if (Number.isNaN(value.getTime())) return { date: '—', time: '—' };
  return {
    date: value.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }),
    time: value.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' })
  };
}
function severity(site) {
  if (site.days_left === null || site.days_left === undefined) return 'unknown';
  if (site.days_left <= 30) return 'red';
  if (site.days_left <= 60) return 'yellow';
  if (site.days_left <= 90) return 'blue';
  return 'green';
}
function attention(site) {
  return !!site.last_error || site.tls_verified === false || (site.days_left !== null && site.days_left <= 30) || ['warning','critical'].includes(site.stale_status);
}
function daysLabel(days) {
  if (days === null || days === undefined) return 'Pending';
  if (days < 0) return `${Math.abs(days)}d overdue`;
  if (days === 0) return '< 1 day';
  return `${days} days`;
}
function toast(message, isError = false) {
  const el = $('toast');
  el.textContent = message;
  el.classList.toggle('error', isError);
  el.classList.add('show');
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => el.classList.remove('show'), 5200);
}
async function api(path, method = 'GET', data = null) {
  const options = { method, headers: {} };
  if (data !== null) {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(data);
  }
  const response = await fetch(path, options);
  const text = await response.text();
  let result;
  try { result = JSON.parse(text); } catch (_) { result = { detail: text }; }
  if (!response.ok) {
    const msg = typeof result.detail === 'string' ? result.detail : `HTTP ${response.status}`;
    throw new Error(msg);
  }
  return result;
}

function renderStats() {
  const sites = state.sites;
  $('totalCount').textContent = sites.length;
  // Count expiry-green certificates, even when a separate trust or connection issue exists.
  // The Needs attention card independently tracks TLS errors and failed checks.
  $('healthyCount').textContent = sites.filter(s => severity(s) === 'green').length;
  $('warningCount').textContent = sites.filter(s => s.days_left !== null && s.days_left <= 60).length;
  $('issuesCount').textContent = sites.filter(attention).length;
  $('tzLabel').textContent = 'Schedule: ' + state.timezone;
  const stale = sites.filter(s => ['warning','critical'].includes(s.stale_status));
  if ($('staleBanner')) { $('staleBanner').hidden = !stale.length;
    $('staleBanner').textContent = `${stale.length} site(s) without a successful check for over 24 hours (including ${stale.filter(s=>s.stale_status==='critical').length} over 48h).`; }
}
function buildDateCell(value, fallback = null) {
  const cell = element('td');
  if (!value) {
    add(cell, element('div', 'small-muted', fallback || '—'));
    return cell;
  }
  const parsed = dateParts(value);
  add(cell, element('div', 'date-top', parsed.date), element('div', 'date-sub', parsed.time));
  const long = new Date(value);
  if (!Number.isNaN(long.getTime())) cell.title = long.toLocaleString();
  return cell;
}
function makeAction(name, svg, title, siteId, disabled = false) {
  const btn = element('button', 'icon-btn' + (name === 'delete' ? ' danger' : ''));
  btn.type = 'button';
  btn.innerHTML = svg; // Hard-coded SVG icon from this script; never server-provided HTML.
  btn.title = title;
  btn.setAttribute('aria-label', title);
  btn.dataset.action = name;
  btn.dataset.id = siteId;
  btn.disabled = disabled;
  return btn;
}
function buildRow(site) {
  const row = element('tr', site.paused ? 'row-paused' : '');
  const urlCell = element('td');
  const urlWrap = element('div', 'site-cell');
  const icon = element('span', 'site-icon'); icon.innerHTML = icons.globe;
  const labels = element('div');
  const siteName = element('div', 'site-name');
  const link = element('a', '', shortHost(site));
  link.href = site.url; link.target = '_blank'; link.rel = 'noopener noreferrer';
  siteName.appendChild(link);
  add(labels, siteName, element('div', 'site-url', site.url));
  if (site.stale_status === 'warning' || site.stale_status === 'critical') {
    const badge = element('span', site.stale_status === 'critical' ? 'stale-tag critical' : 'stale-tag',
      site.stale_status === 'critical' ? '⚠ STALE >48h' : '⚠ STALE >24h');
    badge.title = 'Time since last successful certificate check'; labels.appendChild(badge);
  }
  add(labels, element('span', 'agent-label', '↳ ' + (site.agent_name || 'Primary server')));
  if (site.paused) add(labels, element('span', 'paused-tag', 'PAUSED'));
  else if (site.checking) add(labels, element('span', 'checking-tag', '● CHECKING'));
  add(urlWrap, icon, labels); urlCell.appendChild(urlWrap);

  const issuer = element('td');
  add(issuer, element('div', 'issuer-primary', site.issuer || (site.checking ? 'Checking certificate…' : 'Not checked yet')));
  if (site.last_error) {
    const error = element('div', 'issue-text', '⚠ ' + site.last_error);
    error.title = site.last_error; issuer.appendChild(error);
  } else if (site.tls_verified === false) {
    const error = element('div', 'verify-bad', '⚠ Certificate not trusted / valid');
    error.title = site.verify_error || 'Certificate failed TLS verification'; issuer.appendChild(error);
  } else if (site.tls_verified === true) {
    add(issuer, element('div', 'verify-good', '✓ Trusted TLS connection'));
  }

  const issued = buildDateCell(site.issued_at);
  const expires = buildDateCell(site.expires_at);
  const days = element('td');
  const badge = element('span', 'days-badge ' + severity(site), daysLabel(site.days_left));
  if (site.expires_at) badge.title = 'Remaining at the last check, not live countdown';
  days.appendChild(badge);
  const lastChecked = buildDateCell(site.last_checked_at, site.checking ? 'In progress' : 'Never');
  const nextCheck = buildDateCell(site.paused ? null : site.next_check_at, site.paused ? 'Paused' : 'Awaiting schedule');
  const actions = element('td');
  const group = element('div', 'action-buttons');
  add(group,
    makeAction('certificate', icons.certificate, 'View full certificate information', site.id),
    makeAction('history', icons.history, 'Certificate and check history', site.id),
    makeAction('groups', icons.groups, 'Assign this website to one or more groups', site.id),
    makeAction('agent', icons.globe, 'Choose primary server or remote monitoring agent', site.id),
    makeAction('check', icons.refresh, 'Check certificate now', site.id, site.checking),
    makeAction('pause', site.paused ? icons.play : icons.pause, site.paused ? 'Resume daily checks' : 'Pause daily checks', site.id),
    makeAction('delete', icons.trash, 'Delete site', site.id));
  actions.appendChild(group);
  add(row, urlCell, issuer, issued, expires, days, lastChecked, nextCheck, actions);
  return row;
}
function visibleSites() {
  const query = $('searchBox').value.trim().toLowerCase();
  const scoped = $('searchScope').value === 'group' && state.activeGroup !== 'all';
  const filter = $('statusFilter').value;
  const sort = $('sortSelect').value;
  const data = state.sites.filter(s => {
    const matchesQuery = !query || [s.url, s.issuer, s.last_error].some(v => String(v || '').toLowerCase().includes(query));
    const matchesFilter = filter === 'all' || (filter === 'active' && !s.paused) || (filter === 'paused' && s.paused) || (filter === 'attention' && attention(s)) || (filter === 'stale' && ['warning','critical'].includes(s.stale_status));
    const matchesGroup = !scoped || (s.group_ids || []).includes(Number(state.activeGroup));
    return matchesQuery && matchesFilter && matchesGroup;
  });
  data.sort((a, b) => {
    if (sort === 'name') return a.url.localeCompare(b.url);
    if (sort === 'checked') return (b.last_checked_at || '').localeCompare(a.last_checked_at || '');
    const v1 = a.days_left === null ? Number.POSITIVE_INFINITY : a.days_left;
    const v2 = b.days_left === null ? Number.POSITIVE_INFINITY : b.days_left;
    return v1 - v2 || a.url.localeCompare(b.url);
  });
  return data;
}
function renderTable() {
  const body = $('sitesBody');
  body.replaceChildren();
  const results = visibleSites();
  $('visibleCount').textContent = results.length;
  if (!results.length) {
    const row = element('tr'); const cell = element('td', 'empty-cell');
    cell.colSpan = 8;
    const title = state.sites.length === 0 ? 'No websites added yet' : 'No matching websites';
    const sub = state.sites.length === 0 ? 'Add your first HTTPS website above to start monitoring its certificate.' : 'Try a different search term or filter.';
    add(cell, element('strong', '', title), element('div', '', sub)); row.appendChild(cell); body.appendChild(row);
    return;
  }
  const fragment = document.createDocumentFragment();
  for (const site of results) fragment.appendChild(buildRow(site));
  body.appendChild(fragment);
}
function render() { renderStats(); renderTable(); }

let refreshInFlight = false;
async function refresh(silent = true) {
  if (refreshInFlight) return;
  refreshInFlight = true;
  $('refreshIcon').textContent = '⟳';
  try {
    const [result, agentsData] = await Promise.all([api('/api/sites'), api('/api/agents')]);
    state.agents = agentsData.agents || [];
    renderAgentSelects();
    state.sites = result.sites;
    state.groups = result.groups || [];
    if (state.activeGroup !== 'all' && !state.groups.some(g => g.id === Number(state.activeGroup))) {
      state.activeGroup = 'all';
      $('searchScope').value = 'all';
    }
    renderGroupTabs();
    state.timezone = result.timezone;
    state.loading = false;
    render();
    $('updatedLabel').textContent = 'Updated ' + new Date().toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit', second: '2-digit' });
    if (!silent) toast('Certificate inventory refreshed');
  } catch (error) {
    if (!silent) toast('Could not refresh: ' + error.message, true);
    $('updatedLabel').textContent = 'Connection error — unable to refresh';
  } finally {
    refreshInFlight = false;
    $('refreshIcon').textContent = '↻';
  }
}

// Persistent multi-membership groups. ALL is a virtual tab and can never be removed.
function renderGroupTabs() {
  const target = $('groupTabs');
  target.replaceChildren();
  const entries = [{id: 'all', name: 'ALL', site_count: state.sites.length}, ...state.groups];
  for (const group of entries) {
    const button = element('button', 'group-tab' + (String(group.id) === String(state.activeGroup) ? ' active' : ''));
    button.type = 'button';
    button.dataset.group = String(group.id);
    button.setAttribute('role', 'tab');
    button.setAttribute('aria-selected', String(group.id) === String(state.activeGroup) ? 'true' : 'false');
    button.append(document.createTextNode(group.name + ' '), element('span', 'group-count', group.site_count));
    target.appendChild(button);
  }
  const selected = state.groups.find(g => g.id === Number(state.activeGroup));
  $('manageGroupBtn').hidden = !selected;
  $('groupHint').textContent = selected
    ? `Group: ${selected.name} · ${selected.site_count} websites · ${$('searchScope').value === 'group' ? 'searching this group' : 'searching all websites'}. Use Edit group to choose members from the complete ALL list.`
    : 'ALL includes every monitored website. Create groups to organize websites without duplicating certificate checks.';
}
$('groupTabs').addEventListener('click', event => {
  const button = event.target.closest('button[data-group]');
  if (!button) return;
  state.activeGroup = button.dataset.group;
  $('searchScope').value = state.activeGroup === 'all' ? 'all' : 'group';
  renderGroupTabs(); renderTable();
});
$('searchScope').addEventListener('change', renderGroupTabs);

let editingGroup = null;
let lastGroupFocus = null;
let groupModalSaving = false;
function showDialog(id) {
  lastGroupFocus = document.activeElement;
  $(id).hidden = false;
  document.body.classList.add('cert-modal-open');
  $(id).querySelector('.cert-modal').focus();
}
function hideDialog(id) {
  $(id).hidden = true;
  if ($('groupModal').hidden && $('siteGroupsModal').hidden && $('certificateModal').hidden && $('historyModal').hidden)
    document.body.classList.remove('cert-modal-open');
  if (lastGroupFocus && lastGroupFocus.isConnected) lastGroupFocus.focus();
  lastGroupFocus = null;
}
function selectionCount() {
  const n = $('groupSiteChecklist').querySelectorAll('input:checked').length;
  $('groupSelectionCount').textContent = `${n} selected`;
}
function buildCheckbox(label, checked, value, parent) {
  const row = element('label', 'group-check-row');
  const input = document.createElement('input');
  input.type = 'checkbox'; input.value = String(value); input.checked = checked;
  row.append(input, element('span', '', label));
  parent.appendChild(row);
}
function openGroupEditor(groupId = null) {
  const group = state.groups.find(g => g.id === groupId);
  editingGroup = group || null;
  $('groupModalTitle').textContent = group ? `Edit ${group.name}` : 'Create group';
  $('groupName').value = group ? group.name : '';
  $('groupSaveBtn').textContent = group ? 'Save group' : 'Create group';
  $('groupDeleteBtn').hidden = !group;
  $('groupModalSub').textContent = 'Select websites from ALL; check or uncheck membership. Websites can belong to multiple groups.';
  const list = $('groupSiteChecklist'); list.replaceChildren();
  for (const site of [...state.sites].sort((a,b) => a.url.localeCompare(b.url))) {
    buildCheckbox(site.url, !!group && (site.group_ids || []).includes(group.id), site.id, list);
  }
  if (!state.sites.length) list.appendChild(element('div', 'group-empty', 'No websites yet. You can create an empty group now.'));
  selectionCount();
  showDialog('groupModal');
  $('groupName').focus();
}
$('addGroupBtn').addEventListener('click', () => openGroupEditor());
$('manageGroupBtn').addEventListener('click', () => openGroupEditor(Number(state.activeGroup)));
$('groupModalClose').addEventListener('click', () => hideDialog('groupModal'));
$('groupCancelBtn').addEventListener('click', () => hideDialog('groupModal'));
$('groupModal').addEventListener('click', e => { if (e.target === $('groupModal')) hideDialog('groupModal'); });
$('groupSiteChecklist').addEventListener('change', selectionCount);
$('groupSelectAll').addEventListener('click', () => {
  $('groupSiteChecklist').querySelectorAll('input[type=checkbox]').forEach(el => { el.checked = true; });
  selectionCount();
});
$('groupSelectNone').addEventListener('click', () => {
  $('groupSiteChecklist').querySelectorAll('input[type=checkbox]').forEach(el => { el.checked = false; });
  selectionCount();
});
$('groupForm').addEventListener('submit', async event => {
  event.preventDefault();
  if (groupModalSaving) return;
  const name = $('groupName').value.trim();
  const site_ids = [...$('groupSiteChecklist').querySelectorAll('input:checked')].map(el => Number(el.value));
  groupModalSaving = true; $('groupSaveBtn').disabled = true;
  try {
    if (editingGroup) {
      await api(`/api/groups/${editingGroup.id}`, 'PUT', { name, site_ids });
      toast(`Group ${name} saved`);
    } else {
      const created = await api('/api/groups', 'POST', { name, site_ids });
      state.activeGroup = String(created.id);
      $('searchScope').value = 'group';
      toast(`Group ${name} created`);
    }
    hideDialog('groupModal'); await refresh();
  } catch (err) { toast(err.message, true); }
  finally { groupModalSaving = false; $('groupSaveBtn').disabled = false; }
});
$('groupDeleteBtn').addEventListener('click', async () => {
  if (!editingGroup || !confirm(`Delete group "${editingGroup.name}"? Websites and monitoring data will NOT be deleted.`)) return;
  const deleted = editingGroup.name;
  try {
    await api(`/api/groups/${editingGroup.id}`, 'DELETE');
    state.activeGroup = 'all'; $('searchScope').value = 'all';
    hideDialog('groupModal'); await refresh(); toast(`Group ${deleted} deleted; websites retained`);
  } catch (err) { toast(err.message, true); }
});

let editingSiteId = null;
function openSiteGroups(site) {
  editingSiteId = site.id;
  $('siteGroupsHost').textContent = site.url;
  const list = $('siteGroupsChecklist'); list.replaceChildren();
  for (const group of state.groups) buildCheckbox(group.name, (site.group_ids || []).includes(group.id), group.id, list);
  if (!state.groups.length) list.appendChild(element('div', 'group-empty', 'No groups created yet. Click + New group in the inventory to get started.'));
  showDialog('siteGroupsModal');
}
$('siteGroupsClose').addEventListener('click', () => hideDialog('siteGroupsModal'));
$('siteGroupsCancel').addEventListener('click', () => hideDialog('siteGroupsModal'));
$('siteGroupsModal').addEventListener('click', e => { if (e.target === $('siteGroupsModal')) hideDialog('siteGroupsModal'); });
$('siteGroupsForm').addEventListener('submit', async e => {
  e.preventDefault();
  if (!editingSiteId) return;
  const group_ids = [...$('siteGroupsChecklist').querySelectorAll('input:checked')].map(el => Number(el.value));
  $('siteGroupsSave').disabled = true;
  try {
    await api(`/api/sites/${editingSiteId}/groups`, 'PUT', { group_ids });
    hideDialog('siteGroupsModal'); await refresh(); toast('Website group memberships updated');
  } catch (err) { toast(err.message, true); }
  finally { $('siteGroupsSave').disabled = false; }
});
document.addEventListener('keydown', event => {
  if (event.key !== 'Escape') return;
  if (!$('groupModal').hidden) hideDialog('groupModal');
  if (!$('siteGroupsModal').hidden) hideDialog('siteGroupsModal');
  if (!$('historyModal').hidden) hideDialog('historyModal');
});

$('addForm').addEventListener('submit', async event => {
  event.preventDefault();
  const urls = $('sitesInput').value.trim();
  if (!urls) return;
  $('addBtn').disabled = true;
  $('addFeedback').textContent = 'Adding and queueing initial checks…';
  try {
    const groups = state.activeGroup === 'all' ? [] : [Number(state.activeGroup)];
    const agent_id = $('addAgentSelect').value ? Number($('addAgentSelect').value) : null;
    const result = await api('/api/sites', 'POST', { urls, group_ids: groups, agent_id });
    const count = result.added.length;
    const notes = [];
    if (count) notes.push(`${count} website${count === 1 ? '' : 's'} added`);
    if (result.duplicates.length) notes.push(`${result.duplicates.length} already on list`);
    if (result.errors.length) notes.push(`${result.errors.length} invalid`);
    const message = notes.join(' · ') || 'Nothing added';
    $('addFeedback').textContent = message;
    toast(message + (result.errors.length ? ` — ${result.errors.map(e => `${e.url}: ${e.error}`).join('; ')}` : ''), !!result.errors.length);
    if (count) $('sitesInput').value = '';
    await refresh();
  } catch (error) {
    $('addFeedback').textContent = error.message;
    toast(error.message, true);
  } finally { $('addBtn').disabled = false; }
});

$('sitesBody').addEventListener('click', async event => {
  const button = event.target.closest('button[data-action]');
  if (!button) return;
  const siteId = Number(button.dataset.id);
  const site = state.sites.find(s => s.id === siteId);
  if (!site) return;
  const action = button.dataset.action;
  if (action === 'certificate') { openCertificate(site); return; }
  if (action === 'history') { openHistory(site); return; }
  if (action === 'groups') { openSiteGroups(site); return; }
  if (action === 'agent') { openAgentAssignment(site); return; }
  if (action === 'delete' && !window.confirm(`Delete ${site.url} from monitoring? This cannot be undone.`)) return;
  button.disabled = true;
  try {
    if (action === 'delete') { await api(`/api/sites/${siteId}`, 'DELETE'); toast(`${site.url} deleted`); }
    if (action === 'pause') {
      const paused = !site.paused;
      await api(`/api/sites/${siteId}/pause`, 'POST', { paused });
      toast(`${site.url} ${paused ? 'paused' : 'resumed; certificate check queued'}`);
    }
    if (action === 'check') { await api(`/api/sites/${siteId}/check`, 'POST'); toast(`Checking ${site.url} now`); }
    await refresh();
  } catch (error) { toast(error.message, true); button.disabled = false; }
});

$('refreshBtn').addEventListener('click', () => refresh(false));
$('exportBtn').addEventListener('click', () => { window.location.href = '/api/export.csv'; });
$('exportInventoryBtn').addEventListener('click', () => { window.location.href='/api/export-inventory.csv'; });
$('backupBtn').addEventListener('click', () => { window.location.href='/api/export.json'; });
$('importBtn').addEventListener('click', () => $('importFile').click());
$('importFile').addEventListener('change', async e => {
  const file = e.target.files[0]; if (!file) return;
  if (file.size > 2000000) { toast('Import file exceeds 2MB',true); return; }
  const format = file.name.toLowerCase().endsWith('.json') ? 'json' : file.name.toLowerCase().endsWith('.csv') ? 'csv' : null;
  if (!format) { toast('Select a CSV or JSON file',true); return; }
  if (!confirm(`Import ${file.name}? Existing entries retain certificate history and memberships; imported paused settings will be applied.`)) return;
  $('importBtn').disabled=true;
  try {
    const response = await api('/api/import','POST',{ format, content: await file.text() });
    await refresh(); toast(`Imported: ${response.created} created, ${response.updated} updated`);
  } catch(err) { toast('Import failed: '+err.message,true); }
  finally { $('importFile').value=''; $('importBtn').disabled=false; }
});
['searchBox', 'searchScope', 'statusFilter', 'sortSelect'].forEach(id => $(id).addEventListener(id === 'searchBox' ? 'input' : 'change', renderTable));
refresh();
setInterval(() => { if (!document.hidden) refresh(); }, 10000);


// Certificate viewer — fields come from the PEM captured at the last successful check.
// Always use textContent for certificate fields, as they are remote, untrusted data.
let lastCertificateFocus = null;
let openCertificateId = null;
let savedCertificatePem = '';
async function openHistory(site) {
  $('historyModalHost').textContent=site.url;
  $('historyVersions').textContent='Loading certificate versions…';
  $('historyChecks').textContent='Loading check history…';
  showDialog('historyModal');
  try {
    const result=await api(`/api/sites/${site.id}/history`);
    const versions=$('historyVersions'); versions.replaceChildren();
    if (!result.certificates.length) versions.appendChild(element('p','small-muted','No certificate snapshots captured yet.'));
    for (let i=0;i<result.certificates.length;i++) {
      const cert=result.certificates[i];
      const block=element('div','history-item');
      const title=element('strong','',`${cert.issuer || 'Unknown issuer'} · Expires ${dateParts(cert.expires_at).date}`);
      const type=i===0 ? 'LATEST OBSERVED' : 'PREVIOUS CERTIFICATE';
      const meta=element('div','small-muted',`${type} · First seen ${formattedDate(cert.first_seen_at)} · Last seen ${formattedDate(cert.last_seen_at)}`);
      const detail=element('div','small-muted',`Issued ${formattedDate(cert.issued_at)} · SHA256 ${cert.fingerprint.slice(0,20)}…`);
      if (cert.expiration_delta_days !== undefined && cert.expiration_delta_days !== null) {
        const days=cert.expiration_delta_days;
        block.appendChild(element('div', days < 0 ? 'history-diff negative' : 'history-diff',
          `${days > 0 ? '+' : ''}${days} days vs previous certificate${cert.issuer_changed ? ' · Issuer changed' : ''}`));
      }
      const a=element('a','ghost-btn','Download PEM');a.href=`/api/sites/${site.id}/history/${cert.id}.pem`;
      a.setAttribute('download','');
      block.append(title,meta,detail,a); versions.appendChild(block);
    }
    const checks=$('historyChecks');checks.replaceChildren();
    if (!result.checks.length) checks.appendChild(element('p','small-muted','No checks recorded since upgrading to v4.3.'));
    for (const check of result.checks) {
      const item=element('div','history-item history-check');
      item.append(element('strong','',check.success ? '✓ Certificate retrieved' : '⚠ Connection failed'),
        element('span','small-muted',formattedDate(check.checked_at)),
        element('p','',check.message || (check.success ? `Days left: ${check.days_left ?? '—'} · TLS trusted: ${check.tls_verified===null?'Unknown':check.tls_verified?'Yes':'No'}` : 'No details')));
      checks.appendChild(item);
    }
  } catch(err) { $('historyVersions').textContent='History unavailable: '+err.message; $('historyChecks').textContent=''; }
}
$('historyCloseTop').addEventListener('click',()=>hideDialog('historyModal'));
$('historyCloseBottom').addEventListener('click',()=>hideDialog('historyModal'));
$('historyModal').addEventListener('click',e=>{if(e.target===$('historyModal'))hideDialog('historyModal');});

function closeCertificate() {
  const modal = $('certificateModal');
  if (modal.hidden) return;
  modal.hidden = true;
  document.body.classList.remove('cert-modal-open');
  openCertificateId = null;
  savedCertificatePem = '';
  if (lastCertificateFocus && lastCertificateFocus.isConnected) lastCertificateFocus.focus();
  lastCertificateFocus = null;
}
function certField(label, value, options = {}) {
  const wrapper = element('div', 'cert-field' + (options.wide ? ' wide' : ''));
  const heading = element('dt', 'cert-field-label', label);
  const desc = element('dd', 'cert-field-value' + (options.mono ? ' mono' : ''));
  if (Array.isArray(value)) {
    if (value.length) {
      const chips = element('div', 'cert-chip-list');
      value.forEach(item => chips.appendChild(element('span', 'cert-chip', item)));
      desc.appendChild(chips);
    } else desc.textContent = 'Not present';
  } else desc.textContent = value || '—';
  add(wrapper, heading, desc);
  return wrapper;
}
function formattedDate(value) {
  if (!value) return '—';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString() + ' (' + value + ')';
}
async function openCertificate(site) {
  lastCertificateFocus = document.activeElement;
  openCertificateId = site.id;
  savedCertificatePem = '';
  const modal = $('certificateModal');
  modal.hidden = false;
  document.body.classList.add('cert-modal-open');
  $('certificateModalHost').textContent = site.url;
  $('certificateStatus').textContent = 'Loading saved certificate…';
  $('certificateStatus').className = 'cert-state';
  $('certificateFields').replaceChildren();
  $('certificatePemSection').hidden = true;
  $('certificatePemSection').open = false;
  $('certificateCopyBtn').hidden = true;
  $('certificateDownloadBtn').hidden = true;
  modal.querySelector('.cert-modal').focus();

  try {
    const data = await api(`/api/sites/${site.id}/certificate`);
    if (openCertificateId !== site.id || modal.hidden) return;
    const cert = data.certificate;
    if (!cert) {
      $('certificateStatus').classList.add('warning');
      $('certificateStatus').textContent = data.last_error
        ? `No saved certificate yet. Latest check failed: ${data.last_error}. Use the refresh icon in this site's Actions to retry.`
        : 'No saved certificate details yet. Run Check certificate now from this site’s Actions and reopen this view when it finishes.';
      return;
    }
    savedCertificatePem = cert.pem || '';
    const observed = data.observed_at ? formattedDate(data.observed_at) : 'Unknown';
    let status = `Certificate captured: ${observed}. `;
    if (data.last_error) {
      status += `Warning: the most recent check failed (${data.last_error}). This is the last successfully retrieved certificate.`;
      $('certificateStatus').classList.add('warning');
    } else if (data.tls_verified === false) {
      status += `TLS verification failed: ${data.verify_error || 'Untrusted/invalid certificate'}`;
      $('certificateStatus').classList.add('warning');
    } else {
      status += 'TLS trust verified at capture.';
      $('certificateStatus').classList.add('success');
    }
    $('certificateStatus').textContent = status;
    const fields = $('certificateFields');
    add(fields,
      certField('Subject (Distinguished Name)', cert.subject, {wide:true}),
      certField('Issuer (Distinguished Name)', cert.issuer, {wide:true}),
      certField('Valid from', formattedDate(cert.issued_at)),
      certField('Valid until', formattedDate(cert.expires_at)),
      certField('Serial number (hex)', cert.serial_number, {mono:true,wide:true}),
      certField('DNS subject alternative names', cert.dns_names, {wide:true}),
      certField('IP subject alternative names', cert.ip_addresses, {wide:true}),
      certField('Version', cert.version),
      certField('Signature algorithm', cert.signature_algorithm),
      certField('Public key', cert.public_key),
      certField('Basic constraints', cert.basic_constraints),
      certField('Key usage', cert.key_usage, {wide:true}),
      certField('Extended key usage', cert.extended_key_usage, {wide:true}),
      certField('SHA-256 fingerprint', cert.sha256_fingerprint, {mono:true,wide:true}),
      certField('SHA-1 fingerprint', cert.sha1_fingerprint, {mono:true,wide:true})
    );
    if (savedCertificatePem) {
      $('certificatePemText').textContent = savedCertificatePem;
      $('certificatePemSection').hidden = false;
      $('certificateCopyBtn').hidden = false;
      $('certificateDownloadBtn').hidden = false;
      $('certificateDownloadBtn').href = `/api/sites/${site.id}/certificate.pem`;
    }
  } catch (err) {
    if (openCertificateId !== site.id || modal.hidden) return;
    $('certificateStatus').classList.add('warning');
    $('certificateStatus').textContent = `Unable to load certificate: ${err.message}`;
  }
}
$('certificateCloseTop').addEventListener('click', closeCertificate);
$('certificateCloseBottom').addEventListener('click', closeCertificate);
$('certificateModal').addEventListener('click', event => {
  if (event.target === $('certificateModal')) closeCertificate();
});
document.addEventListener('keydown', event => {
  if ($('certificateModal').hidden) return;
  if (event.key === 'Escape') { event.preventDefault(); closeCertificate(); }
  if (event.key === 'Tab') {
    // Keep keyboard focus in the certificate dialog while open.
    const controls = [...$('certificateModal').querySelectorAll('button:not([hidden]),a:not([hidden]),summary')]
      .filter(el => !el.closest('[hidden]'));
    const first = controls[0], last = controls[controls.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  }
});
$('certificateCopyBtn').addEventListener('click', async () => {
  if (!savedCertificatePem) return;
  try {
    await navigator.clipboard.writeText(savedCertificatePem);
    toast('Certificate PEM copied to clipboard');
  } catch (err) {
    toast('Clipboard unavailable. Expand Raw certificate (PEM) to copy manually.', true);
  }
});


// Integration settings are fetched only when the accordion is opened.
// Never store API keys or signing secrets in localStorage, cookies, or query strings.
let settingsLoaded = false;
async function loadIntegrations() {
  try {
    const data = await api('/api/settings');
    const k = data.api_key;
    $('apiKeyStatus').textContent = k.configured ? 'Active key' : 'No key';
    $('apiKeyStatus').classList.toggle('enabled', k.configured);
    $('apiKeyMeta').textContent = k.configured ? `Active: ${k.prefix} • Generated ${formattedDate(k.created_at)}` : 'No active key';
    $('revokeApiKey').disabled = !k.configured;
    const w = data.webhook;
    $('webhookEnabled').checked = w.enabled;
    $('webhookUrl').value = w.url;
    $('webhookAllowHttp').checked = w.allow_http;
    $('webhookAllowPrivate').checked = w.allow_private;
    $('webhookAllowSelfSigned').checked = w.allow_self_signed;
    const selected = new Set(w.events);
    document.querySelectorAll('#webhookEvents input[type=checkbox]').forEach(box => { box.checked = selected.has(box.value); });
    $('webhookStatus').textContent = w.enabled ? 'Enabled' : 'Disabled';
    $('webhookStatus').classList.toggle('enabled', w.enabled);
    $('webhookSecretMeta').textContent = w.secret_configured ? 'Signing secret configured (not shown again)' : 'Signing secret generated on first save';
    $('testWebhook').disabled = !w.enabled;
    renderWebhookTargets(data.targets || []);
    const list = $('deliveryHistory');
    list.replaceChildren();
    if (!data.deliveries.length) {
      list.textContent = 'No webhook deliveries yet.';
    } else {
      for (const delivery of data.deliveries) {
        const row = element('div', 'delivery-entry');
        const left = element('div');
        left.appendChild(element('strong', '', delivery.event.replace(/_/g,' ')));
        const related = (data.targets || []).find(t=>t.id === delivery.target_id);
        const description = [related ? related.name : 'Default webhook', formattedDate(delivery.created_at), `${delivery.attempts} attempt(s)`];
        if (delivery.response_code) description.push(`HTTP ${delivery.response_code}`);
        if (delivery.last_error) description.push(delivery.last_error);
        left.appendChild(element('small', '', description.join(' · ')));
        const status = element('span', 'delivery-status ' + delivery.status, delivery.status);
        row.append(left, status); list.appendChild(row);
      }
    }
    settingsLoaded = true;
  } catch (err) { toast('Could not load integrations: ' + err.message, true); }
}
$('integrationAccordion').addEventListener('toggle', () => {
  if ($('integrationAccordion').open) loadIntegrations();
});
$('generateApiKey').addEventListener('click', async () => {
  if ($('apiKeyStatus').textContent === 'Active key' && !confirm('Rotate the API key? The existing key will immediately stop working.')) return;
  try {
    const result = await api('/api/settings/api-key', 'POST', {});
    $('apiKeyOutput').value = result.api_key;
    $('apiKeyReveal').hidden = false;
    await loadIntegrations();
    toast('API key generated. Copy it now; it cannot be retrieved later.');
  } catch (err) { toast(err.message, true); }
});
$('revokeApiKey').addEventListener('click', async () => {
  if (!confirm('Revoke the active API key? Remote API queries will immediately fail.')) return;
  try {
    await api('/api/settings/api-key', 'DELETE');
    $('apiKeyReveal').hidden = true;
    $('apiKeyOutput').value = '';
    await loadIntegrations();
    toast('API key revoked');
  } catch (err) { toast(err.message, true); }
});
$('webhookForm').addEventListener('submit', async event => {
  event.preventDefault();
  $('saveWebhook').disabled = true;
  try {
    const selection = [...document.querySelectorAll('#webhookEvents input[type=checkbox]:checked')].map(box => box.value);
    const result = await api('/api/settings/webhook', 'PUT', {
      enabled: $('webhookEnabled').checked, url: $('webhookUrl').value.trim(), events: selection,
      allow_http: $('webhookAllowHttp').checked, allow_private: $('webhookAllowPrivate').checked,
      allow_self_signed: $('webhookAllowSelfSigned').checked
    });
    if (result.signing_secret) {
      $('webhookSecretOutput').value = result.signing_secret;
      $('webhookSecretReveal').hidden = false;
    }
    await loadIntegrations();
    toast('Webhook settings saved');
  } catch (err) { toast(err.message, true); }
  finally { $('saveWebhook').disabled = false; }
});
$('rotateWebhookSecret').addEventListener('click', async () => {
  if (!confirm('Rotate the webhook signing secret? Update the receiver before your next delivery.')) return;
  try {
    const result = await api('/api/settings/webhook/rotate-secret', 'POST', {});
    $('webhookSecretOutput').value = result.signing_secret;
    $('webhookSecretReveal').hidden = false;
    await loadIntegrations();
    toast('New signing secret generated; copy it now.');
  } catch (err) { toast(err.message, true); }
});
$('testWebhook').addEventListener('click', async () => {
  $('testWebhook').disabled = true;
  try {
    await api('/api/settings/webhook/test', 'POST', {});
    toast('Test delivery queued. Check delivery status shortly.');
    setTimeout(loadIntegrations, 3000);
  } catch (err) { toast(err.message, true); }
  finally { $('testWebhook').disabled = false; }
});
document.querySelectorAll('button[data-copy]').forEach(button => {
  button.addEventListener('click', async () => {
    const field = $(button.dataset.copy);
    try {
      await navigator.clipboard.writeText(field.value);
      toast('Copied to clipboard');
    } catch (_) {
      field.focus(); field.select();
      toast('Select and copy the highlighted value.');
    }
  });
});

// Additional independent webhook destinations with group selectors (v4.3).
let webhookTargets=[];
let activeWebhookTarget=null;
let availableWebhookEvents=[];
function renderWebhookTargets(targets) {
  webhookTargets=targets;
  const list=$('webhookTargetsList');list.replaceChildren();
  if(!targets.length)list.appendChild(element('div','setup-help','No additional destinations configured.'));
  for(const target of targets) {
    const row=element('div','target-row');
    const left=element('div');
    left.append(element('strong','',target.name+(target.enabled?' · enabled':' · disabled')),
      element('small','',target.url + ' · '+(target.all_groups ? 'ALL websites' : target.group_ids.length ? target.group_ids.map(id=>state.groups.find(g=>g.id===id)?.name || 'Unknown group').join(', ') : 'NO GROUPS — not delivering')));
    const btns=element('div','target-actions');
    for(const [label,action] of [['Edit','edit'],['Test','test'],['Rotate','rotate'],['Delete','delete']]) {
      const button=element('button','ghost-btn',label);button.type='button';button.dataset.targetAction=action;
      button.dataset.targetId=target.id;btns.appendChild(button);
    }
    row.append(left,btns);list.appendChild(row);
  }
}
function openTargetEditor(target=null) {
  activeWebhookTarget=target;
  $('targetFormTitle').textContent=target ? 'Edit '+target.name : 'New webhook destination';
  $('targetName').value=target?.name || '';
  $('targetEnabled').checked=target?.enabled ?? true;
  $('targetUrl').value=target?.url || '';
  $('targetAllowHttp').checked=target?.allow_http ?? false;
  $('targetAllowPrivate').checked=target?.allow_private ?? false;
  $('targetAllowSelfSigned').checked=target?.allow_self_signed ?? false;
  const groups=$('targetGroups');groups.replaceChildren();
  const selected=new Set(target?.group_ids || []);
  for(const group of state.groups) buildCheckbox(group.name,selected.has(group.id),group.id,groups);
  if (!state.groups.length) groups.appendChild(element('div','small-muted','No named groups yet. This destination will apply to ALL.'));
  const events=$('targetEvents');events.replaceChildren();
  const eventList=['expiration_90','expiration_60','expiration_30','certificate_expired','tls_invalid',
    'check_failed','recovered','certificate_changed','certificate_renewed','certificate_issuer_changed',
    'certificate_expiration_shortened','monitoring_stale_warning','monitoring_stale_critical','needs_attention','attention_cleared'];
  const active=new Set(target?.events || eventList);
  for(const name of eventList) buildCheckbox(name.replace(/_/g,' '),active.has(name),name,events);
  $('targetWebhookForm').hidden=false;
  $('targetWebhookForm').scrollIntoView({behavior:'smooth',block:'nearest'});
}
$('newWebhookTarget').addEventListener('click',()=>openTargetEditor());
$('targetCancel').addEventListener('click',()=>{$('targetWebhookForm').hidden=true;});
$('targetWebhookForm').addEventListener('submit',async e=>{
  e.preventDefault();
  const body={name:$('targetName').value.trim(),enabled:$('targetEnabled').checked,url:$('targetUrl').value.trim(),
    allow_http:$('targetAllowHttp').checked,allow_private:$('targetAllowPrivate').checked,
    allow_self_signed:$('targetAllowSelfSigned').checked,
    group_ids:[...$('targetGroups').querySelectorAll('input:checked')].map(box=>Number(box.value)),
    events:[...$('targetEvents').querySelectorAll('input:checked')].map(box=>box.value)};
  $('targetSave').disabled=true;
  try {
    const result=await api(activeWebhookTarget ? `/api/settings/webhooks/${activeWebhookTarget.id}` : '/api/settings/webhooks',
      activeWebhookTarget?'PUT':'POST',body);
    if(result.signing_secret){$('targetSecretOutput').value=result.signing_secret;$('targetSecretReveal').hidden=false;}
    $('targetWebhookForm').hidden=true;await loadIntegrations();toast('Webhook destination saved');
  } catch(err){toast(err.message,true);}finally{$('targetSave').disabled=false;}
});
$('webhookTargetsList').addEventListener('click',async e=>{
  const button=e.target.closest('button[data-target-action]');if(!button)return;
  const target=webhookTargets.find(t=>t.id===Number(button.dataset.targetId));if(!target)return;
  const action=button.dataset.targetAction;
  if(action==='edit'){openTargetEditor(target);return;}
  if(action==='delete'&&!confirm(`Delete destination ${target.name}?`))return;
  if(action==='rotate'&&!confirm(`Rotate signing secret for ${target.name}?`))return;
  button.disabled=true;
  try{
    const result=await api(`/api/settings/webhooks/${target.id}`+(action==='test'?'/test':action==='rotate'?'/rotate-secret':''),
      action==='delete'?'DELETE':'POST',action==='delete'?null:{});
    if(result.signing_secret){$('targetSecretOutput').value=result.signing_secret;$('targetSecretReveal').hidden=false;}
    toast(action==='test'?'Test delivery queued':action==='rotate'?'New signing secret generated':'Destination deleted');
    await loadIntegrations();
  }catch(err){toast(err.message,true);}finally{button.disabled=false;}
});


// v4.4: agent enrollment, connectivity display and website assignment.
let editingAgentSite = null;
function renderAgentSelects() {
  for (const id of ['addAgentSelect', 'assignAgentSelect']) {
    const sel = $(id); const previous = sel.value;
    sel.replaceChildren(new Option('Primary server (local)', ''));
    for (const agent of state.agents) {
      if (agent.enabled || (id === 'assignAgentSelect' && editingAgentSite && editingAgentSite.agent_id === agent.id)) {
        sel.add(new Option(agent.name + ' — ' + agent.status, String(agent.id)));
      }
    }
    sel.value = [...sel.options].some(o => o.value === previous) ? previous : '';
  }
}
function openAgentAssignment(site) {
  editingAgentSite = site;
  $('assignAgentWebsite').textContent = site.url;
  renderAgentSelects();
  $('assignAgentSelect').value = site.agent_id === null ? '' : String(site.agent_id);
  showDialog('assignAgentModal');
}
function closeAgentAssignment() { hideDialog('assignAgentModal'); editingAgentSite = null; }
$('assignAgentClose').addEventListener('click', closeAgentAssignment);
$('assignAgentCancel').addEventListener('click', closeAgentAssignment);
$('assignAgentModal').addEventListener('click', e => { if (e.target === $('assignAgentModal')) closeAgentAssignment(); });
$('assignAgentForm').addEventListener('submit', async e => {
  e.preventDefault();
  if (!editingAgentSite) return;
  const id = editingAgentSite.id;
  const agent_id = $('assignAgentSelect').value ? Number($('assignAgentSelect').value) : null;
  try {
    await api(`/api/sites/${id}/agent`, 'PUT', { agent_id });
    closeAgentAssignment(); await refresh(); toast('Monitoring location updated; check queued');
  } catch (err) { toast(err.message, true); }
});
async function loadAgents() {
  try {
    const data = await api('/api/agents');
    state.agents = data.agents || [];
    renderAgentSelects();
    const list = $('agentsList'); list.replaceChildren();
    if (!state.agents.length) { list.textContent = 'No agents configured. Create one above to get a pairing code.'; return; }
    for (const a of state.agents) {
      const entry = element('div','agent-entry');
      const info = element('div');
      info.append(element('strong', '', a.name), element('span','agent-pill '+a.status,a.status.toUpperCase()));
      info.appendChild(element('small', '', `${a.site_count} website(s) · Last contact: ${a.last_seen_at ? formattedDate(a.last_seen_at) : 'Never'}`));
      const actions = element('div', 'agent-entry-actions');
      for (const [label, action] of [['Pair','pair'],[a.enabled?'Disable':'Enable','toggle'],['Delete','delete']]) {
        const btn = element('button', 'ghost-btn', label); btn.type='button';
        btn.addEventListener('click', async () => {
          if (action === 'delete' && !confirm(`Delete ${a.name}? Its websites will move to the primary server.`)) return;
          if (action === 'toggle' && a.enabled && !confirm(`Disable ${a.name}? Remote certificate checks will stop until re-enabled.`)) return;
          try {
            if (action === 'pair') {
              const result=await api(`/api/agents/${a.id}/pair`,'POST',{});
              $('agentCode').value=result.enrollment_code; $('agentEnrollment').hidden=false;
              toast('New pairing code generated; previous agent token remains active until paired again.');
            } else if (action === 'toggle') await api(`/api/agents/${a.id}`,'PUT',{enabled:!a.enabled});
            else await api(`/api/agents/${a.id}`,'DELETE');
            await loadAgents();
          } catch (err) { toast(err.message,true); }
        });
        actions.appendChild(btn);
      }
      entry.append(info,actions); list.appendChild(entry);
    }
  } catch (err) { toast('Agent list could not load: '+err.message,true); }
}
$('agentAccordion').addEventListener('toggle', () => { if ($('agentAccordion').open) loadAgents(); });
$('createAgentForm').addEventListener('submit', async e => {
  e.preventDefault();
  try {
    const response = await api('/api/agents','POST',{name:$('newAgentName').value.trim()});
    $('newAgentName').value='';
    $('agentCode').value=response.enrollment_code; $('agentEnrollment').hidden=false;
    await loadAgents(); toast('Agent created. Copy the pairing code into its setup page.');
  } catch (err) { toast(err.message,true); }
});
