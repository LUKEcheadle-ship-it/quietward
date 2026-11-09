"""Exercise the CLI-selected HTTP page and its JavaScript with a minimal DOM.

Node checks state transitions deterministically; these are not native browser QA.
"""
import http.client
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from quietward.cli import DashboardServer
from quietward.config import DashboardSettings, StorageSettings
from quietward.enhanced_dashboard import QuietWardDashboardServer


class ServedDashboardUXTests(unittest.TestCase):
    def served_html(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = DashboardServer(DashboardSettings(bind='127.0.0.1', port=0),
                                     StorageSettings(root / 'db', root / 'alerts'))
            server.start()
            try:
                connection = http.client.HTTPConnection(*server.address, timeout=3)
                connection.request('GET', '/')
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                html = response.read().decode()
                connection.request('GET', '/api/overview?limit=100')
                overview_response = connection.getresponse()
                self.assertEqual(overview_response.status, 200)
                overview = json.loads(overview_response.read())
                self.assertIn('finding_groups', overview)
                self.assertEqual(overview['display_limit'], 100)
                self.assertEqual(overview['actions_executed'], 0)
                connection.close()
                return html
            finally:
                server.close()

    def test_cli_serves_shared_ux_and_operations(self):
        self.assertIs(DashboardServer, QuietWardDashboardServer)
        html = self.served_html()
        for marker in ('How to use QuietWard', 'Raw Event Log', 'count-note',
                       'refresh-status', 'Incident lifecycle', 'Monitoring coverage',
                       'Bounded local retention', '/api/overview?limit=100'):
            self.assertIn(marker, html)
        self.assertNotIn('v0.5 development dashboard', html)
        self.assertEqual(html.count('setInterval('), 1)
        self.assertLess(html.index('id="welcome"'), html.index('id="findings"'))

    @unittest.skipUnless(shutil.which('node'), 'Node required for deterministic JavaScript checks')
    def test_served_javascript_interactions(self):
        html = self.served_html()
        script = re.search(r'<script>(.*?)</script>', html, re.S).group(1)
        harness = r'''
const vm=require('node:vm'),assert=require('node:assert/strict');
const input=JSON.parse(require('node:fs').readFileSync(0,'utf8'));
const ids=[...input.html.matchAll(/id="([^"]+)"/g)].map(m=>m[1]);
const elements=new Map();
function element(){return {innerHTML:'',textContent:'',value:'',hidden:false,disabled:false,className:'',focus(){this.focused=true},classList:{add(){},remove(){}},querySelectorAll(){return []}}}
for(const id of ids)elements.set(id,element());
const get=id=>{assert.ok(elements.has(id),'Missing served element '+id);return elements.get(id)};
const pending=[],timers=[],storage=new Map();let blocked=false;
const context=vm.createContext({console,Set,Date,Intl,Number,encodeURIComponent,
 document:{getElementById:get},
 localStorage:{getItem(k){if(blocked)throw Error('blocked');return storage.get(k)},setItem(k,v){if(blocked)throw Error('blocked');storage.set(k,v)},removeItem(k){if(blocked)throw Error('blocked');storage.delete(k)}},
 fetch(url,options){assert.ok(url.startsWith('/api/'));assert.equal(options.method,undefined);return new Promise((resolve,reject)=>pending.push({url,resolve,reject}))},
 setInterval(fn,ms){timers.push(fn);assert.equal(ms,60000);return timers.length}
});
vm.runInContext(input.script,context);
const run=code=>vm.runInContext(code,context);
const reply=(request,data,ok=true)=>request.resolve({ok,status:ok?200:503,json:async()=>data});
const flush=async()=>{for(let i=0;i<10;i++)await Promise.resolve()};
(async()=>{
 assert.equal(timers.length,1);assert.equal(pending.length,1);assert.equal(get('refresh').disabled,true);
 await get('refresh').onclick();timers[0]();assert.equal(pending.length,1,'overlap rejected');
 const high={finding_id:'high',title:'<script>attack</script>',severity:'high',score:90,created_at:'2026-08-13T12:00:00Z',review:{state:'open'}};
 const low={...high,finding_id:'low',severity:'low',review:{state:'resolved'}};
 const data={findings:[high,low],finding_groups:[{group_key:'g',title:high.title,findings:[high,low]}],raw_finding_count:2,
 summary:{evidence_chain:{valid:true}},lifecycle:{active:1,incidents:2,transitions:3},incidents:[],
 coverage:{resolution_safe:false,degraded_count:1,domains:[{name:'<img>',state:'degraded',reason_code:'<svg>'}]},
 retention:{retention_days:30,capacities:[{name:'<img>',current:1,limit:10,utilization:0.1}]}};
 reply(pending.shift(),data);await flush();
 assert.equal(get('refresh').disabled,false);assert.match(get('refresh-status').innerHTML,/Last refreshed/);
 assert.match(get('count-note').textContent,/1 group.*2 matching raw/);assert.match(get('findings').innerHTML,/&lt;script&gt;/);
 assert.ok(!get('findings').innerHTML.includes('<script>'));assert.match(get('coverage-domains').innerHTML,/&lt;img&gt;/);
 assert.match(get('life-sub').textContent,/1 active/);assert.match(get('retention').innerHTML,/10% utilized/);
 run("state.expanded.add('g')");get('severity').value='high';get('severity').onchange();
 assert.match(get('count-note').textContent,/1 matching raw/);assert.ok(get('findings').innerHTML.includes('data-group="g" open'));
 get('review').value='resolved';get('review').onchange();assert.match(get('findings').innerHTML,/No findings match/);
 get('review').value='';get('review').onchange();const before=get('findings').innerHTML;
 const refresh=get('refresh').onclick();assert.match(get('refresh-status').textContent,/Refreshing/);
 pending.shift().reject(Error('<network>'));await refresh;
 assert.equal(get('findings').innerHTML,before);assert.equal(get('severity').value,'high');
 get('severity').onchange();assert.match(get('status').textContent,/previous data/);
 assert.match(get('refresh-status').innerHTML,/&lt;network&gt;/);assert.match(get('status').textContent,/previous data/);
 const malformed=get('refresh').onclick();reply(pending.shift(),{findings:[]});await malformed;
 assert.equal(get('findings').innerHTML,before);assert.match(get('refresh-status').innerHTML,/Malformed/);
 const brokenRender=get('refresh').onclick();reply(pending.shift(),{...data,finding_groups:[null]});await brokenRender;
 assert.equal(get('findings').innerHTML,before);get('severity').onchange();assert.equal(get('findings').innerHTML,before);
 const recover=get('refresh').onclick();reply(pending.shift(),data);await recover;assert.match(get('refresh-status').innerHTML,/Last refreshed/);
 get('dismiss-help').onclick();assert.equal(get('welcome').hidden,true);assert.equal(storage.size,1);assert.equal(get('help').focused,true);
 get('help').onclick();assert.equal(get('welcome').hidden,false);assert.equal(storage.size,0);
 blocked=true;get('dismiss-help').onclick();get('help').onclick();assert.equal(get('welcome').hidden,false);
 const first=run("openFinding('old')"),second=run("openFinding('new')");const a=pending.shift(),b=pending.shift();
 reply(b,{finding:{title:'New',severity:'high',reason_explanations:['Human explanation <safe>'],reasons:['raw<event>']}});await second;
 reply(a,{finding:{title:'Old'}});await first;assert.equal(get('drawer-title').textContent,'New');
 assert.match(get('drawer-body').innerHTML,/Human explanation &lt;safe&gt;/);assert.match(get('drawer-body').innerHTML,/raw&lt;event&gt;/);
 assert.match(get('drawer-body').innerHTML,/Raw Event Log/);
 const late=run("openFinding('late')");get('close').onclick();reply(pending.shift(),{finding:{title:'Late'}});await late;
 assert.equal(get('drawer-title').textContent,'New');
 blocked=false;storage.set('quietward-welcome-dismissed','1');get('welcome').hidden=false;
 vm.runInContext(input.script,vm.createContext({...context}));assert.equal(get('welcome').hidden,true);
 console.log('Served dashboard state, escaping, filters, details, operations and refresh: PASS');
})().catch(error=>{console.error(error);process.exitCode=1});
'''
        result = subprocess.run([shutil.which('node'), '-e', harness],
                                input=json.dumps({'html': html, 'script': script}),
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('PASS', result.stdout)
