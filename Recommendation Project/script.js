// page scroller

const prevButtons = document.querySelectorAll(".prev-button");
const nextButtons = document.querySelectorAll(".next-button");
const cardContainers = document.querySelectorAll(".card-container");

function scrollToRight(container) {
  container.scrollBy({
    top: 0,
    left: 600, // Adjust the scroll amount based on card width
    behavior: "smooth",
  });
}

function scrollToLeft(container) {
  container.scrollBy({
    top: 0,
    left: -600, // Adjust the scroll amount based on  card width
    behavior: "smooth",
  });
}

// Bind the events to the buttons
for (let i = 0; i < prevButtons.length; i++) {
  prevButtons[i].addEventListener("click", () => {
    scrollToLeft(cardContainers[i]);
  });
}

for (let i = 0; i < nextButtons.length; i++) {
  nextButtons[i].addEventListener("click", () => {
    scrollToRight(cardContainers[i]);
  });
}

// sign up
$(document).ready(function () {
  // 点击“登录/注册”按钮时，显示注册表单
  $("#authModal").on("show.bs.modal", function (event) {
    $("#register-form").show();
    $("#login-form").hide();
    $("#authModalLabel").text("Sign up");
  });

  // 点击“切换到登录”链接时，显示登录表单
  $("#switch-to-login").click(function () {
    $("#register-form").hide();
    $("#login-form").show();
    $("#authModalLabel").text("Log in");
  });

  // 点击“切换到注册”链接时，显示注册表单
  $("#switch-to-register").click(function () {
    $("#register-form").show();
    $("#login-form").hide();
    $("#authModalLabel").text("Sign up");
  });

  // 在提交表单时，执行相应的登录或注册操作
  $("form").submit(function (event) {
    event.preventDefault();
    // TODO: 在这里编写登录或注册的代码
  });
});
