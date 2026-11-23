const navToggle = document.querySelector(".nav-toggle");
const navigation = document.querySelector("#main-navigation");
const mobileViewport = window.matchMedia("(max-width: 767px)");

function updateNavigationLayout() {
  navToggle.hidden = !mobileViewport.matches;
  navigation.hidden = mobileViewport.matches;
  navToggle.setAttribute("aria-expanded", String(!navigation.hidden));
}

navToggle.addEventListener("click", () => {
  navigation.hidden = !navigation.hidden;
  navToggle.setAttribute("aria-expanded", String(!navigation.hidden));
});

mobileViewport.addEventListener("change", updateNavigationLayout);
updateNavigationLayout();
