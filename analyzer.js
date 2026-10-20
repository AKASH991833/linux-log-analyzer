'use strict';
(function(){
var MON={Jan:0,Feb:1,Mar:2,Apr:3,May:4,Jun:5,Jul:6,Aug:7,Sep:8,Oct:9,Nov:10,Dec:11};
var RE_SYS=/^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+([^\s:\[]+)(?:\[(\d+)\])?:\s*(.*)$/;
var RE_ISO=/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+(\S+)\s+([^\s:\[]+)(?:\[(\d+)\])?:\s*(.*)$/;
var IP='((?:\\d{1,3}\\.){3}\\d{1,3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+)';
var R={
 failed:new RegExp('Failed (\\S+) for (invalid user )?(\\S+) from '+IP+'(?: port (\\d+))?'),
 invalid:new RegExp('Invalid user (\\S*) from '+IP),
 accepted:new RegExp('Accepted (\\S+) for (\\S+) from '+IP+'(?: port (\\d+))?'),
 maxauth:new RegExp('maximum authentication attempts exceeded for (?:invalid user )?(\\S+) from '+IP),
 noident:new RegExp('Did not receive identification string from '+IP),
 preauth:new RegExp('(?:Connection closed|Connection reset|Disconnected from|Timeout, client not responding).*?(?:by |from )(?:authenticating user (\\S+) |invalid user (\\S+) )?'+IP+'.*\\[preauth\\]'),
 pamfail:new RegExp('authentication failure;.*rhost='+IP+'(?:\\s+user=(\\S+))?'),
 sudo:/^\s*(\S+)\s*:\s*(?:TTY=([^;]*);\s*)?(?:PWD=([^;]*);\s*)?USER=(\S+)\s*;\s*COMMAND=(.*)$/,
 sudofail:/(\d+ incorrect password attempts?|authentication failure).*?(?:user=(\S+)|;\s*(\S+)\s*:)?/,
 sessopen:/session opened for user (\S+?)(?:\(uid=\d+\))?(?: by (\S+))?/,
 newuser:/new user: name=([^,\s]+)/, delusr:/delete user '([^']+)'/, pwchg:/password changed for (\S+)/, grp:/add '([^']+)' to (?:shadow )?group '([^']+)'/,
 oom:/Out of memory: Kill(?:ed)? process (\d+) \(([^)]+)\)/, err:/\b(error|failed|failure|denied|critical|segfault|panic|refused|timed out|timeout)\b/i
};
function isPrivate(ip){return /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip)||ip==='::1'||/^f[cd]/i.test(ip)}
function parse(text,defYear){
  var lines=text.split(/\r?\n/),ev=[],lastM=-1,year=defYear,total=0,unparsed=0,skipped=0;
  for(var i=0;i<lines.length;i++){var ln=lines[i];if(!ln.trim())continue;total++;
    var m,ts=null,host,proc,pid,msg;
    if((m=RE_ISO.exec(ln))){ts=new Date(+m[1],+m[2]-1,+m[3],+m[4],+m[5],+m[6]).getTime();host=m[7];proc=m[8];pid=m[9];msg=m[10]}
    else if((m=RE_SYS.exec(ln))&&MON[m[1]]!==undefined){var mo=MON[m[1]];if(lastM>=0&&mo<lastM-5)year++;lastM=mo;ts=new Date(year,mo,+m[2],+m[3],+m[4],+m[5]).getTime();host=m[6];proc=m[7];pid=m[8];msg=m[9]}
    else{unparsed++;continue}
    if(isNaN(ts)){unparsed++;continue}
    proc=proc.replace(/\[\d+\]$/,'');var e={ts:ts,host:host,proc:proc,pid:pid,msg:msg,line:i+1},x;
    if((x=R.failed.exec(msg))){e.type='failed';e.method=x[1];e.user=x[3];e.ip=x[4];e.invalid=!!x[2]}
    else if((x=R.accepted.exec(msg))){e.type='accepted';e.method=x[1];e.user=x[2];e.ip=x[3]}
    else if((x=R.invalid.exec(msg))){e.type='invalid';e.user=x[1];e.ip=x[2]}
    else if((x=R.maxauth.exec(msg))){e.type='maxauth';e.user=x[1];e.ip=x[2]}
    else if((x=R.noident.exec(msg))){e.type='noident';e.ip=x[1]}
    else if(proc==='sudo'&&(x=R.sudo.exec(msg))){e.type='sudo';e.user=x[1];e.target=x[4];e.cmd=x[5].trim()}
    else if(/^sshd/.test(proc)&&(x=R.preauth.exec(msg))){e.type='preauth';e.user=x[1]||x[2]||'';e.ip=x[3]}
    else if((x=R.pamfail.exec(msg))){e.type='pamfail';e.ip=x[1];e.user=x[2]||''}
    else if(proc==='sudo'&&R.sudofail.test(msg)&&/incorrect password|authentication failure/.test(msg)){e.type='sudofail';e.user=(/user=(\S+)/.exec(msg)||[])[1]||''}
    else if((x=R.newuser.exec(msg))){e.type='useradd';e.user=x[1]}
    else if((x=R.delusr.exec(msg))){e.type='userdel';e.user=x[1]}
    else if((x=R.pwchg.exec(msg))){e.type='passwd';e.user=x[1]}
    else if((x=R.grp.exec(msg))){e.type='groupadd';e.user=x[1];e.group=x[2]}
    else if((x=R.oom.exec(msg))){e.type='oom';e.cmd=x[2]}
    else if((x=R.sessopen.exec(msg))&&/sshd|login|su|sudo/.test(proc)){e.type='session';e.user=x[1]}
    else if(R.err.test(msg)){e.type='error'}
    else{skipped++;continue}
    ev.push(e)}
  return {events:ev,total:total,unparsed:unparsed,other:skipped}}
function analyse(text,defYear){
  var p=parse(text,defYear),ev=p.events,ips={},users={},ok=[],sudo=[],acc=[],svc={},hours={},first=null,last=null;
  var st={failed:0,invalid:0,accepted:0,sudo:0,sudofail:0,oom:0};
  ev.forEach(function(e){if(first===null||e.ts<first)first=e.ts;if(last===null||e.ts>last)last=e.ts;
    var isFail=e.type==='failed'||e.type==='invalid'||e.type==='maxauth'||e.type==='pamfail';
    if(e.type==='failed'||e.type==='invalid')st[e.type==='failed'?'failed':'invalid']++;
    if(e.type==='accepted')st.accepted++;if(e.type==='sudo')st.sudo++;if(e.type==='sudofail')st.sudofail++;if(e.type==='oom')st.oom++;
    var hk=new Date(e.ts);hk=new Date(hk.getFullYear(),hk.getMonth(),hk.getDate(),hk.getHours()).getTime();
    if(e.type==='failed'||e.type==='accepted'){var h=hours[hk]||(hours[hk]={t:hk,f:0,a:0});if(e.type==='failed')h.f++;else h.a++}
    if(e.type==='failed'&&e.ip){var o=ips[e.ip]||(ips[e.ip]={ip:e.ip,n:0,users:{},first:e.ts,last:e.ts,times:[],ok:0,priv:isPrivate(e.ip),invalid:0});o.n++;o.users[e.user]=(o.users[e.user]||0)+1;if(e.ts<o.first)o.first=e.ts;if(e.ts>o.last)o.last=e.ts;o.times.push(e.ts);if(e.invalid)o.invalid++;
      var u=users[e.user]||(users[e.user]={user:e.user,n:0,ips:{},invalid:0});u.n++;u.ips[e.ip]=1;if(e.invalid)u.invalid++}
    else if(e.type==='invalid'&&e.ip){var o2=ips[e.ip]||(ips[e.ip]={ip:e.ip,n:0,users:{},first:e.ts,last:e.ts,times:[],ok:0,priv:isPrivate(e.ip),invalid:0});o2.invalid++}
    if(e.type==='accepted')ok.push(e);if(e.type==='sudo')sudo.push(e);
    if(e.type==='useradd'||e.type==='userdel'||e.type==='passwd'||e.type==='groupadd')acc.push(e);
    if(e.type==='error'||e.type==='oom'){var s=svc[e.proc]||(svc[e.proc]={proc:e.proc,n:0,sample:e.msg});s.n++}});
  var list=Object.keys(ips).map(function(k){var o=ips[k];o.times.sort(function(a,b){return a-b});var burst=0,j=0;for(var i=0;i<o.times.length;i++){while(o.times[i]-o.times[j]>300000)j++;if(i-j+1>burst)burst=i-j+1}o.burst=burst;o.usersN=Object.keys(o.users).length;o.brute=o.n>=10||burst>=5;return o}).filter(function(o){return o.n>0}).sort(function(a,b){return b.n-a.n});
  // success after failures from same IP
  var suspicious=[];ok.forEach(function(e){var o=ips[e.ip];if(o&&o.n>=3&&o.first<=e.ts){o.ok++;suspicious.push({ip:e.ip,user:e.user,ts:e.ts,fails:o.n})}});
  var ul=Object.keys(users).map(function(k){var u=users[k];u.ipsN=Object.keys(u.ips).length;return u}).sort(function(a,b){return b.n-a.n});
  var sl=Object.keys(svc).map(function(k){return svc[k]}).sort(function(a,b){return b.n-a.n});
  var hl=Object.keys(hours).map(function(k){return hours[k]}).sort(function(a,b){return a.t-b.t});
  var rootTry=ul.filter(function(u){return u.user==='root'})[0];
  return {p:p,events:ev,st:st,ips:list,users:ul,ok:ok,sudo:sudo,acc:acc,svc:sl,hours:hl,first:first,last:last,suspicious:suspicious,rootTry:rootTry}}
window.LogAnalyzer={parse:parse,analyse:analyse,isPrivate:isPrivate};
})();
