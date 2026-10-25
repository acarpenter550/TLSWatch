// No browser libraries required: execute the actual Live Inventory filtering function.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname,'..','static','app.js'), 'utf8');
const start = source.indexOf('function visibleSites() {');
const end = source.indexOf('function renderTable()', start);
assert(start !== -1 && end !== -1);
const code = source.substring(start,end);
const form = {searchBox:'',searchScope:'group',statusFilter:'all',sortSelect:'name'};
const sites = [
 {id:1,url:'https://a.example',issuer:'CA One',days_left:150,group_ids:[3],paused:false},
 {id:2,url:'https://b.example',issuer:'CA Two',days_left:20,group_ids:[3,4],paused:false},
 {id:3,url:'https://c.example',issuer:'CA Two',days_left:180,group_ids:[4],paused:true},
 {id:4,url:'https://d.example',issuer:'CA One',days_left:null,group_ids:[],paused:false},
];
const context = vm.createContext({ state:{activeGroup:'3',sites}, $:name=>({value:form[name]}), attention:s=> s.days_left!==null&&s.days_left<=30 });
vm.runInContext(code, context);
const ids = () => Array.from(vm.runInContext('visibleSites().map(s=>s.id)',context));
assert.deepEqual(ids(), [1,2]);
form.searchBox='CA Two'; assert.deepEqual(ids(), [2]);
form.searchBox='';form.searchScope='all';assert.deepEqual(ids(),[1,2,3,4]);
form.statusFilter='paused';assert.deepEqual(ids(),[3]);
form.statusFilter='attention';form.searchScope='group';assert.deepEqual(ids(),[2]);
form.statusFilter='all';context.state.activeGroup='4';assert.deepEqual(ids(),[2,3]);
context.state.activeGroup='all';assert.deepEqual(ids(),[1,2,3,4]);
console.log('Group tab/search scope and status filtering: PASS');
