'use strict';
(function(){
var $=function(s){return document.querySelector(s)},A=window.LogAnalyzer,res=null;
function toast(m){var t=$('#toast');t.textContent=m;t.classList.add('show');clearTimeout(toast.t);toast.t=setTimeout(function(){t.classList.remove('show')},2200)}
function el(tag,cls,txt){var e=document.createElement(tag);if(cls)e.className=cls;if(txt!==undefined)e.textContent=txt;return e}
var MN=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
function p2(n){return n<10?'0'+n:''+n}
function fmt(ts){var d=new Date(ts);return d.getDate()+' '+MN[d.getMonth()]+' '+d.getFullYear()+' '+p2(d.getHours())+':'+p2(d.getMinutes())+':'+p2(d.getSeconds())}
function fmtH(ts){var d=new Date(ts);return d.getDate()+' '+MN[d.getMonth()]+' '+p2(d.getHours())+':00'}
function table(id,head,rows,empty){var t=$(id);t.replaceChildren();if(!rows.length){var r=el('tr'),c=el('td',null,empty||'Nothing found.');c.colSpan=head.length;r.append(c);t.append(r);return}
  var th=el('thead'),hr=el('tr');head.forEach(function(h){hr.append(el('th',null,h))});th.append(hr);t.append(th);var tb=el('tbody');
  rows.forEach(function(row){var tr=el('tr');row.forEach(function(c,i){var td=el('td',typeof c==='number'?'n':(c&&c.m?'m':''));if(c&&c.pill){var s=el('span','pill '+c.pill,c.t);td.append(s)}else td.textContent=(c&&c.t!==undefined)?c.t:c;tr.append(td)});tb.append(tr)});t.append(tb)}
function stat(label,val,cls){var d=el('div','stat'+(cls?' '+cls:''));d.append(el('b',null,String(val)),el('span',null,label));return d}
function chart(h){
  var box=$('#chart');box.replaceChildren();if(!h.length){box.textContent='No SSH login events with timestamps.';return}
  // fill gaps
  var step=3600000,from=h[0].t,to=h[h.length-1].t,map={};h.forEach(function(x){map[x.t]=x});var all=[];for(var t=from;t<=to&&all.length<24*60;t+=step)all.push(map[t]||{t:t,f:0,a:0});
  var max=1;all.forEach(function(x){if(x.f>max)max=x.f;if(x.a>max)max=x.a});
  var bw=Math.max(14,Math.min(34,900/all.length)),W=all.length*bw+40,H=190,ns='http://www.w3.org/2000/svg';
  var svg=document.createElementNS(ns,'svg');svg.setAttribute('width',W);svg.setAttribute('height',H);svg.setAttribute('viewBox','0 0 '+W+' '+H);svg.setAttribute('role','img');svg.setAttribute('aria-label','Failed and accepted SSH logins per hour');
  function rect(x,y,w,h2,fill,title){var r=document.createElementNS(ns,'rect');r.setAttribute('x',x);r.setAttribute('y',y);r.setAttribute('width',w);r.setAttribute('height',Math.max(0,h2));r.setAttribute('rx',3);r.setAttribute('fill',fill);var tt=document.createElementNS(ns,'title');tt.textContent=title;r.append(tt);svg.append(r)}
  var cs=getComputedStyle(document.documentElement),bad=cs.getPropertyValue('--bad').trim()||'#fb7185',ok=cs.getPropertyValue('--ok').trim()||'#34d399';
  all.forEach(function(x,i){var X=30+i*bw,ph=140;var fh=x.f/max*ph,ah=x.a/max*ph;
    rect(X+1,150-fh,bw/2-1,fh,bad,fmtH(x.t)+': '+x.f+' failed');rect(X+bw/2,150-ah,bw/2-1,ah,ok,fmtH(x.t)+': '+x.a+' accepted');
    if(all.length<=30||i%Math.ceil(all.length/24)===0){var t=document.createElementNS(ns,'text');t.setAttribute('x',X+bw/2);t.setAttribute('y',168);t.setAttribute('text-anchor','middle');t.textContent=p2(new Date(x.t).getHours());svg.append(t);if(new Date(x.t).getHours()===0||i===0){var t2=document.createElementNS(ns,'text');t2.setAttribute('x',X);t2.setAttribute('y',183);t2.textContent=new Date(x.t).getDate()+' '+MN[new Date(x.t).getMonth()];svg.append(t2)}}});
  var yl=document.createElementNS(ns,'text');yl.setAttribute('x',2);yl.setAttribute('y',14);yl.textContent=max;svg.append(yl);
  var ln=document.createElementNS(ns,'line');ln.setAttribute('x1',28);ln.setAttribute('x2',W);ln.setAttribute('y1',150);ln.setAttribute('y2',150);ln.setAttribute('stroke',cs.getPropertyValue('--line').trim()||'#444');svg.append(ln);box.append(svg)}
var EVL={failed:'Failed login',accepted:'Accepted login',invalid:'Invalid user',maxauth:'Max auth tries',noident:'No SSH banner',preauth:'Closed pre-auth',pamfail:'PAM auth failure',sudo:'sudo command',sudofail:'sudo failure',useradd:'User added',userdel:'User deleted',passwd:'Password changed',groupadd:'Group change',oom:'Out of memory',session:'Session opened',error:'Error/warning'};
function evRows(){var q=$('#evq').value.trim().toLowerCase(),ty=$('#evt').value;return res.events.filter(function(e){return (!ty||e.type===ty)&&(!q||(e.msg+' '+(e.ip||'')+' '+(e.user||'')+' '+e.proc).toLowerCase().indexOf(q)>=0)})}
function renderEv(){var r=evRows();$('#evc').textContent='('+r.length+' of '+res.events.length+', showing first 500)';table('#tEv',['Time','Type','Source IP','User','Detail'],r.slice(0,500).map(function(e){return [fmt(e.ts),EVL[e.type]||e.type,{m:1,t:e.ip||''},e.user||'',{m:1,t:(e.cmd||e.msg).slice(0,160)}]}))}
function recs(r){
  var out=[],br=r.ips.filter(function(o){return o.brute&&!o.priv});
  if(r.suspicious.length)out.push(['hi','A login succeeded from an IP that had failed attempts: '+r.suspicious.map(function(s){return s.ip+' (user '+s.user+')'}).filter(function(v,i,a){return a.indexOf(v)===i}).join(', ')+'. Treat this as possible compromise. Check the account, active sessions and what was run.',['last -a | head','who','sudo grep -E "COMMAND|useradd|passwd" /var/log/auth.log | tail -50']]);
  if(r.acc.some(function(e){return e.type==='useradd'}))out.push(['hi','New user account(s) created: '+r.acc.filter(function(e){return e.type==='useradd'}).map(function(e){return e.user}).join(', ')+'. If you did not create them, lock and investigate.',['getent passwd | tail','sudo passwd -l USERNAME']]);
  if(br.length)out.push(['','Brute-force pattern from '+br.length+' public IP(s). Install fail2ban to ban repeat offenders automatically, or block with your firewall after review.',['sudo apt install fail2ban','sudo systemctl enable --now fail2ban','sudo fail2ban-client status sshd']]);
  if(r.rootTry)out.push(['','Attackers tried root '+r.rootTry.n+' times. Disable direct root login in /etc/ssh/sshd_config (PermitRootLogin no), then reload SSH.',['sudo grep -i permitrootlogin /etc/ssh/sshd_config','sudo sshd -t && sudo systemctl reload ssh']]);
  if(r.st.failed>=20)out.push(['','Use SSH keys and turn off password login once your key works (PasswordAuthentication no). Keep a second session open while testing.',['ssh-keygen -t ed25519','ssh-copy-id user@server']]);
  if(r.st.failed>=20)out.push(['','Consider a non-default port or allow-listing your own IPs in the firewall for SSH. This reduces noise but is not real security by itself.',['sudo ufw allow from YOUR_IP to any port 22 proto tcp']]);
  if(r.st.oom)out.push(['','Out-of-memory kills found. Check memory use and which process is being killed.',['free -h','sudo dmesg -T | grep -i "killed process"']]);
  if(!out.length)out.push(['','No strong warning signs in this log. Keep logs rotated, keep packages updated and check again regularly.',['sudo apt update && apt list --upgradable']]);
  return out}
function render(){
  var r=res,s=r.st;$('#out').hidden=false;var sb=$('#stats');sb.replaceChildren();
  sb.append(stat('Lines read',r.p.total),stat('Events found',r.events.length),stat('Failed logins',s.failed,s.failed?'bad':''),stat('Invalid-user tries',s.invalid,s.invalid?'warn':''),stat('Accepted logins',s.accepted,'ok'),stat('Attacker IPs',r.ips.filter(function(o){return !o.priv}).length,'warn'),stat('sudo commands',s.sudo),stat('Time range',r.first?fmt(r.first).slice(0,-3)+' to '+fmt(r.last).slice(0,-3):'n/a'));
  sb.lastChild.querySelector('b').style.fontSize='14px';
  var al=$('#alerts');al.replaceChildren();recs(r).forEach(function(x){var d=el('div','alert'+(x[0]?' '+x[0]:''));d.append(el('b',null,x[0]==='hi'?'High priority':'Heads up'),document.createTextNode(x[1]));var pre=el('div','muted small');x[2].forEach(function(c){var k=el('code',null,c);pre.append(k,document.createTextNode(' '))});d.append(pre);al.append(d)});
  chart(r.hours);
  table('#tIp',['IP','Failed','Users tried','First seen','Last seen','Status'],r.ips.slice(0,25).map(function(o){return [{m:1,t:o.ip},o.n,o.usersN,fmt(o.first),fmt(o.last),o.ok?{pill:'bad',t:'Login succeeded'}:o.priv?{pill:'warn',t:'Private IP'}:o.brute?{pill:'bad',t:'Likely brute force'}:{pill:'ok',t:'Low volume'}]}),'No failed SSH logins found.');
  table('#tUser',['Username','Failed','From IPs','Invalid user?'],r.users.slice(0,25).map(function(u){return [u.user,u.n,u.ipsN,u.invalid===u.n?'Yes':u.invalid?'Sometimes':'No']}),'No failed usernames.');
  table('#tOk',['Time','User','From IP','Method'],r.ok.slice(-50).reverse().map(function(e){return [fmt(e.ts),e.user,{m:1,t:e.ip},e.method]}),'No accepted logins in this log.');
  table('#tSudo',['Time','User','As','Command'],r.sudo.slice(-50).reverse().map(function(e){return [fmt(e.ts),e.user,e.target,{m:1,t:e.cmd.slice(0,140)}]}),'No sudo commands.');
  table('#tAcc',['Time','Change','User'],r.acc.map(function(e){return [fmt(e.ts),EVL[e.type]+(e.group?' ('+e.group+')':''),e.user]}),'No user or group changes.');
  table('#tSvc',['Service','Lines','Example'],r.svc.slice(0,15).map(function(x){return [x.proc,x.n,{m:1,t:x.sample.slice(0,90)}]}),'No error lines.');
  var rc=$('#recs');rc.replaceChildren();var tips=[['Never run a block command before you confirm the IP is not yours or a teammate.'],['Keep SSH keys, updates and a firewall in place. Logs show attacks, they do not stop them.']];tips.forEach(function(t){rc.append(el('li',null,t[0]))});
  var tv=$('#evt');while(tv.options.length>1)tv.remove(1);var seen={};r.events.forEach(function(e){seen[e.type]=1});Object.keys(seen).sort().forEach(function(k){var o=el('option',null,EVL[k]||k);o.value=k;tv.append(o)});
  renderEv();$('#out').scrollIntoView({behavior:'smooth',block:'start'})}
function run(){var t=$('#log').value;if(t.trim().length<20){toast('Paste some log lines first');return}
  var y=parseInt($('#year').value,10)||new Date().getFullYear();res=A.analyse(t,y);
  if(!res.events.length){toast('No known events found. Check the log format.');$('#info').textContent='Read '+res.p.total+' lines, '+res.p.unparsed+' not in syslog format. Expected lines like: Oct 20 10:44:50 host sshd[123]: ...';return}
  $('#info').textContent='Read '+res.p.total+' lines. '+res.events.length+' matched events, '+res.p.unparsed+' lines not in syslog/ISO format, '+res.p.other+' ignored as routine.';render()}
function csv(){var q=function(v){v=String(v==null?'':v);if(/^[=+\-@\t\r]/.test(v))v="'"+v;return '"'+v.replace(/"/g,'""')+'"'};var rows=[['time','type','host','process','ip','user','detail']].concat(evRows().map(function(e){return [new Date(e.ts).toISOString(),e.type,e.host,e.proc,e.ip||'',e.user||'',e.cmd||e.msg]}));
  var b=new Blob(['\ufeff'+rows.map(function(r){return r.map(q).join(',')}).join('\r\n')],{type:'text/csv;charset=utf-8'}),u=URL.createObjectURL(b),a=document.createElement('a');a.href=u;a.download='log-events.csv';document.body.appendChild(a);a.click();a.remove();setTimeout(function(){URL.revokeObjectURL(u)},3000)}
function copy(t,m){if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(t).then(function(){toast(m)},function(){toast('Copy not allowed here')});else toast('Copy not supported here')}
function loadFile(f){if(!f)return;if(f.size>25*1024*1024){toast('File is over 25 MB. Paste the last part with tail -n 50000.');return}var fr=new FileReader();fr.onload=function(){$('#log').value=String(fr.result);run()};fr.readAsText(f)}
$('#year').value=new Date().getFullYear();
$('#go').addEventListener('click',run);
$('#sample').addEventListener('click',function(){$('#log').value=window.makeSample(+$('#year').value);run()});
$('#clear').addEventListener('click',function(){$('#log').value='';$('#out').hidden=true;res=null});
$('#file').addEventListener('change',function(e){loadFile(e.target.files[0]);e.target.value=''});
var dz=$('#drop');['dragenter','dragover'].forEach(function(n){dz.addEventListener(n,function(e){e.preventDefault();dz.classList.add('drag')})});['dragleave','drop'].forEach(function(n){dz.addEventListener(n,function(e){e.preventDefault();dz.classList.remove('drag')})});dz.addEventListener('drop',function(e){loadFile(e.dataTransfer.files[0])});
$('#evq').addEventListener('input',function(){if(res)renderEv()});$('#evt').addEventListener('change',function(){if(res)renderEv()});$('#csv').addEventListener('click',function(){if(res)csv()});
$('#copyIps').addEventListener('click',function(){if(!res)return;copy(res.ips.filter(function(o){return o.brute&&!o.priv}).map(function(o){return o.ip}).join('\n'),'IP list copied')});
$('#copyBlock').addEventListener('click',function(){if(!res)return;copy('# REVIEW EACH IP BEFORE RUNNING\n'+res.ips.filter(function(o){return o.brute&&!o.priv&&/^[\d.]+$/.test(o.ip)}).map(function(o){return 'sudo ufw deny from '+o.ip+' to any port 22'}).join('\n'),'Block commands copied')});
document.addEventListener('themechange',function(){if(res)chart(res.hours)});
window.__la={run:run,get res(){return res}};
if('serviceWorker' in navigator&&location.protocol.indexOf('http')===0)navigator.serviceWorker.register('sw.js').catch(function(){});
})();
