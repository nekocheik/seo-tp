let buttons = document.querySelectorAll('.button__menu')
let menu = document.querySelector('nav ul')


buttons.forEach( button => {
  button.addEventListener('click',()=>{
    console.log('olk')
    menu.classList.toggle('active')
  })
});
console.log(menu, buttons)