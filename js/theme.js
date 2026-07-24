(function(){
var STORAGE_KEY='blog-theme',html=document.documentElement;
function getTheme(){var s=localStorage.getItem(STORAGE_KEY);return s||(window.matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light')}
function applyTheme(t){if(t==='dark')html.classList.add('dark');else html.classList.remove('dark');localStorage.setItem(STORAGE_KEY,t)}
applyTheme(getTheme());
window.matchMedia('(prefers-color-scheme:dark)').addEventListener('change',function(e){if(!localStorage.getItem(STORAGE_KEY))applyTheme(e.matches?'dark':'light')});
document.addEventListener('DOMContentLoaded',function(){var b=document.getElementById('theme-toggle');if(b)b.addEventListener('click',function(){applyTheme(html.classList.contains('dark')?'light':'dark')})})
})();