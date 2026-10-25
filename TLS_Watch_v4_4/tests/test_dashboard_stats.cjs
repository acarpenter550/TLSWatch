// Run with: node tests/test_dashboard_stats.cjs
// Execute the dashboard's real calculation code in a tiny DOM mock.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '..', 'static', 'app.js'), 'utf8');
const prefix = source.split('function buildDateCell(')[0];
assert(prefix.includes('function renderStats()'), 'renderStats must be found in app.js');

function summary(sites) {
  const elements = new Map();
  const document = { getElementById: (id) => {
    if (!elements.has(id)) elements.set(id, { textContent: '' });
    return elements.get(id);
  }};
  // Prefix contains the actual severity, attention and renderStats functions.
  const context = vm.createContext({ document });
  vm.runInContext(prefix + '\nstate.sites = ' + JSON.stringify(sites) + '; state.timezone = "America/New_York"; renderStats();', context);
  return Object.fromEntries(['totalCount', 'healthyCount', 'warningCount', 'issuesCount'].map(k => [k, Number(elements.get(k).textContent)]));
}

const sites = [
  {days_left: 150, tls_verified: true, last_error: null},
  {days_left: 110, tls_verified: false, last_error: null}, // Was wrongly excluded by healthy count
  {days_left: 91, tls_verified: true, last_error: 'Temporary check failure'}, // Was wrongly excluded
  {days_left: 90, tls_verified: true, last_error: null},  // Boundary is BLUE, not GREEN
  {days_left: 60, tls_verified: true, last_error: null},
  {days_left: 30, tls_verified: true, last_error: null},
  {days_left: null, tls_verified: null, last_error: null}
];
assert.deepEqual(summary(sites), {totalCount: 7, healthyCount: 3, warningCount: 2, issuesCount: 3});
assert.deepEqual(summary(sites.slice(0, 2)), {totalCount: 2, healthyCount: 2, warningCount: 0, issuesCount: 1});
assert.deepEqual(summary([{days_left: 90, tls_verified: true, last_error: null}]), {totalCount: 1, healthyCount: 0, warningCount: 0, issuesCount: 0});
console.log('Dashboard stat tests: PASS (green count matches expiration badge; trust/check issues separate).');
