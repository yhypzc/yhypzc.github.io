// Navbar transparency scroll effect (Mizuki semifull mode)
(function(){
  var navbar=document.getElementById('navbar');
  if(!navbar||!document.body.classList.contains('has-banner'))return;
  var banner=document.getElementById('home-banner');
  function onScroll(){
    var h=banner?banner.offsetHeight-navbar.offsetHeight:300;
    if(window.scrollY>h)navbar.classList.add('scrolled');
    else navbar.classList.remove('scrolled');
  }
  window.addEventListener('scroll',onScroll,{passive:true});
  onScroll();
})();
