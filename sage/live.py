"""Live dashboard: tiny stdlib HTTP server (127.0.0.1 only) that mirrors the running pipeline."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = r"""<!doctype html><meta charset=utf-8><title>S.A.G.E. live</title>
<style>
:root{color-scheme:dark}body{margin:0;font:14px system-ui,sans-serif;background:#0d1117;color:#e6edf3}
header{padding:14px 22px;border-bottom:1px solid #30363d}h1{font-size:18px;margin:0}small{color:#8b949e}
main{display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:16px 22px}section{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 14px}
h2{font-size:13px;margin:0 0 8px;color:#8b949e;text-transform:uppercase;letter-spacing:.06em}
#nodes{display:flex;flex-wrap:wrap;gap:8px}.n{padding:6px 10px;border-radius:6px;border:1px solid #30363d;font-weight:600}
.pending{color:#8b949e}.running{background:#1f6feb33;border-color:#1f6feb;color:#58a6ff;animation:p 1s infinite alternate}
.succeeded{background:#23863633;border-color:#238636;color:#3fb950}.failed{background:#da363333;border-color:#da3633;color:#f85149}.skipped{color:#6e7681;border-style:dashed}
@keyframes p{to{opacity:.55}}pre{margin:0;max-height:340px;overflow:auto;font:12px ui-monospace,monospace;white-space:pre-wrap}
table{width:100%;border-collapse:collapse;font-size:12px}td,th{padding:3px 6px;border-bottom:1px solid #21262d;text-align:left}
.full{grid-column:1/-1}.sev-critical,.sev-high{color:#f85149}.sev-medium{color:#d29922}.sev-low{color:#8b949e}
</style>
<header><h1>S.A.G.E. <small id=meta></small></h1></header>
<main><section class=full><h2>Pipeline</h2><div id=nodes></div></section>
<section><h2>Live log</h2><pre id=log></pre></section>
<section><h2>Analytics</h2><div id=an>waiting…</div></section>
<section><h2>Findings</h2><div id=fi>waiting…</div></section>
<section><h2>Code review</h2><div id=cr>waiting…</div></section>
<section class=full><h2>Live program run - before vs after</h2><div style="display:grid;grid-template-columns:1fr 1fr;gap:12px"><div><small>BEFORE</small><pre id=bo>waiting...</pre></div><div><small>AFTER</small><pre id=ao>waiting...</pre></div></div></section>
<section class=full><h2>Result</h2><div id=res>running…</div></section></main>
<script>
const $=id=>document.getElementById(id);
function el(t,txt,cls){const e=document.createElement(t);if(txt!==undefined)e.textContent=txt;if(cls)e.className=cls;return e}
function table(rows,head){const t=el('table');if(head){const r=el('tr');head.forEach(h=>r.append(el('th',h)));t.append(r)}
 rows.forEach(c=>{const r=el('tr');c.forEach(x=>r.append(el('td',x.t??x,x.c)));t.append(r)});return t}
async function tick(){let s;try{s=await (await fetch('/state')).json()}catch(e){return}
 $('meta').textContent=`${s.repo} · model ${s.model||'…'} · Groq calls ${s.llm_calls}`;
 const n=$('nodes');n.replaceChildren();s.nodes.forEach(x=>n.append(el('div',({succeeded:'✓ ',failed:'✗ ',running:'▶ ',skipped:'– ',pending:'· '})[x.status]+x.name,'n '+x.status)));
 const l=$('log');const stick=l.scrollTop+l.clientHeight>=l.scrollHeight-30;l.textContent=s.logs.join('\n');if(stick)l.scrollTop=l.scrollHeight;
 const a=s.state.analytics;if(a){$('an').replaceChildren(el('div',`${a.files} files · ${a.total_loc} LOC · ${a.python_functions} functions · avg complexity ${a.avg_complexity} · tests: ${a.has_tests?'yes':'none'} · TODOs ${a.todo_count}`),
  table(a.hotspots.slice(0,5).map(h=>[`${h.file}:${h.line} ${h.name}()`,'cx '+h.complexity]),['Hotspot','Complexity']))}
 const sc=s.state.scan;if(sc){$('fi').replaceChildren(sc.vulnerabilities.length?table(sc.vulnerabilities.slice(0,12).map(v=>[{t:v.severity,c:'sev-'+v.severity},v.rule_id,`${v.file}:${v.line}`]),['Sev','Rule','Where']):el('div','No findings'))}
 const c=s.state.code_review;if(c){const d=el('div');d.append(el('p',c.summary));c.issues.slice(0,6).forEach(i=>d.append(el('div',`[${i.severity}] ${i.file}: ${i.detail}`)));$('cr').replaceChildren(d)}
 if(s.state.before_output!=null)$('bo').textContent=s.state.before_output;if(s.state.after_output!=null)$('ao').textContent=s.state.after_output;
 const r=$('res');const st=s.state;if(st.pr){r.textContent=(st.accepted?'Patch verified and pushed. ':'Review-only branch pushed. ')+'Branch: '+st.pr.branch_name+(st.pr.pr_url?'  PR: '+st.pr.pr_url:'')}
 else if(s.done){r.textContent='Finished without a PR (see log).'}}
setInterval(tick,1000);tick()
</script>"""


def make_handler(pipe, llm):  # type: ignore[no-untyped-def]
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a) -> None:  # silence
            pass

        def _send(self, body: bytes, ctype: str) -> None:
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/state":
                nodes = [{"name": n, "status": pipe.statuses.get(n, "pending")}
                         for n in (pipe.sched.nodes if pipe.sched else pipe.statuses)]
                body = json.dumps({"repo": pipe.state.repo_url, "model": llm.model, "llm_calls": llm.calls,
                                   "nodes": nodes, "logs": pipe.logs[-120:], "done": getattr(pipe, "done", False),
                                   "state": json.loads(pipe.state.model_dump_json(
                                       exclude={"baseline", "final_run", "after_scan", "smoke_baseline"}))})
                self._send(body.encode(), "application/json")
            elif self.path in ("/", "/index.html"):
                self._send(PAGE.encode(), "text/html; charset=utf-8")
            else:
                self.send_error(404)
    return H


class LiveServer:
    def __init__(self, pipe, llm, port: int = 0) -> None:  # type: ignore[no-untyped-def]
        self._srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(pipe, llm))
        self.url = f"http://127.0.0.1:{self._srv.server_address[1]}/"
        self._t = threading.Thread(target=self._srv.serve_forever, daemon=True)

    def start(self) -> str:
        self._t.start()
        return self.url

    def stop(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()
