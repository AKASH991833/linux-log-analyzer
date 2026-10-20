(function(){var k='akash-tools-theme',r=document.documentElement,t;try{t=localStorage.getItem(k)}catch(e){}
if(t!=='light'&&t!=='dark')t=(window.matchMedia&&matchMedia('(prefers-color-scheme: light)').matches)?'light':'dark';
r.setAttribute('data-theme',t);
window.__setTheme=function(n){r.setAttribute('data-theme',n);try{localStorage.setItem(k,n)}catch(e){}var b=document.getElementById('themeBtn');if(b)b.textContent=n==='light'?'🌙 Dark':'☀️ Light';document.dispatchEvent(new CustomEvent('themechange',{detail:n}))};
document.addEventListener('DOMContentLoaded',function(){var b=document.getElementById('themeBtn');if(!b)return;b.textContent=r.getAttribute('data-theme')==='light'?'🌙 Dark':'☀️ Light';b.addEventListener('click',function(){window.__setTheme(r.getAttribute('data-theme')==='light'?'dark':'light')})});
})();
