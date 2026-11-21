// Dark is the default; the owner's choice is remembered in this browser.
(function(){
  var root=document.documentElement,key='relay-theme';
  function read(){try{return localStorage.getItem(key)==='light'?'light':'dark'}catch(e){return 'dark'}}
  function apply(theme){
    if(theme==='light')root.setAttribute('data-theme','light');else root.removeAttribute('data-theme');
    var buttons=document.querySelectorAll('[data-theme-toggle]');
    for(var i=0;i<buttons.length;i++){
      buttons[i].setAttribute('aria-pressed',theme==='light'?'true':'false');
      buttons[i].title=theme==='light'?'Включить тёмную тему':'Включить светлую тему';
    }
  }
  apply(read());
  document.addEventListener('DOMContentLoaded',function(){
    apply(read());
    const menu = document.querySelector('.fc-server-menu');
    if (menu) {
      const compactNavigation = window.matchMedia('(max-width: 840px)');
      const resizeMenu = () => { menu.open = !compactNavigation.matches; };
      resizeMenu();
      compactNavigation.addEventListener('change', resizeMenu);
    }
    document.addEventListener('click',function(event){
      var button=event.target.closest&&event.target.closest('[data-theme-toggle]');
      if(!button)return;
      var next=read()==='light'?'dark':'light';
      try{localStorage.setItem(key,next)}catch(e){}
      apply(next);
    });
  });
})();
