/* Made-up sample log. Uses documentation IP ranges (RFC 5737) and fictional hosts/users. */
window.makeSample=function(year){
  var L=[],mon=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'],seed=7;
  function rnd(){seed=(seed*1103515245+12345)&0x7fffffff;return seed/0x7fffffff}
  function ts(h,m,s){var p=function(n){return (n<10?'0':'')+n};return 'Oct 20 '+p(h)+':'+p(m)+':'+p(s)}
  var ev=[];
  function add(h,m,s,proc,pid,msg){ev.push([h*3600+m*60+s,ts(h,m,s)+' web01 '+proc+'['+pid+']: '+msg])}
  var names=['admin','test','oracle','ubuntu','postgres','user','ftpuser','pi','git','root','guest','support'];
  for(var i=0;i<85;i++){var t=2*3600+Math.floor(rnd()*3600*2),u=names[Math.floor(rnd()*names.length)],inv=u!=='root';
    add(Math.floor(t/3600),Math.floor(t%3600/60),t%60,'sshd',2200+i,'Failed password for '+(inv?'invalid user ':'')+u+' from 203.0.113.9 port '+(40000+i*7)+' ssh2');
    if(inv&&i%5===0)add(Math.floor(t/3600),Math.floor(t%3600/60),t%60,'sshd',2200+i,'Invalid user '+u+' from 203.0.113.9 port '+(40000+i*7))}
  for(var j=0;j<24;j++){var t2=14*3600+j*20+Math.floor(rnd()*10);add(Math.floor(t2/3600),Math.floor(t2%3600/60),t2%60,'sshd',3300+j,'Failed password for root from 198.51.100.23 port '+(51000+j)+' ssh2')}
  add(14,9,30,'sshd',3340,'Accepted password for deploy from 198.51.100.23 port 51999 ssh2');
  add(14,9,30,'sshd',3340,'pam_unix(sshd:session): session opened for user deploy(uid=1002) by (uid=0)');
  for(var k=0;k<6;k++){var t3=9*3600+k*3600*2+120;add(Math.floor(t3/3600),Math.floor(t3%3600/60),t3%60,'sshd',4400+k,'Accepted publickey for student from 192.168.1.20 port '+(52000+k)+' ssh2: RSA SHA256:abcdEXAMPLEkey')}
  for(var q=0;q<5;q++)add(11+q,5,10,'sshd',5000+q,'Failed password for student from 192.168.1.77 port '+(53000+q)+' ssh2');
  add(11,6,0,'sshd',5009,'Accepted password for student from 192.168.1.77 port 53009 ssh2');
  add(9,2,40,'sudo',4500,'student : TTY=pts/0 ; PWD=/home/student ; USER=root ; COMMAND=/usr/bin/apt update');
  add(9,3,10,'sudo',4501,'student : TTY=pts/0 ; PWD=/home/student ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx');
  add(14,12,5,'sudo',3400,'deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/sbin/useradd -m backdoor');
  add(14,12,6,'useradd',3401,"new user: name=backdoor, UID=1003, GID=1003, home=/home/backdoor, shell=/bin/sh");
  add(14,12,30,'passwd',3402,'pam_unix(passwd:chauthtok): password changed for backdoor');
  add(14,13,0,'sudo',3410,'deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow');
  add(16,30,0,'sudo',6000,'pam_unix(sudo:auth): authentication failure; logname=student uid=1001 euid=0 tty=/dev/pts/0 ruser=student rhost=  user=student');
  add(3,15,1,'CRON',700,'pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)');
  add(6,0,2,'systemd',1,'nginx.service: Failed with result \'exit-code\'.');
  add(6,0,5,'systemd',1,'Failed to start A high performance web server.');
  add(18,40,0,'kernel',0,'Out of memory: Killed process 8123 (java) total-vm:4096000kB');
  add(20,1,0,'sshd',7000,'Did not receive identification string from 192.0.2.44 port 40001');
  add(20,2,0,'sshd',7001,'Connection closed by authenticating user admin 192.0.2.45 port 40500 [preauth]');
  ev.sort(function(a,b){return a[0]-b[0]});
  return ev.map(function(e){return e[1]}).join('\n')};
