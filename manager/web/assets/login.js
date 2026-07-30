"use strict";
document.getElementById("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const error = document.getElementById("login-error");
  const button = form.querySelector("button");
  error.hidden = true;
  button.disabled = true;
  try {
    const response = await fetch("/api/v1alpha1/session", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({username: form.username.value, password: form.password.value})
    });
    if (!response.ok) throw new Error("authentication failed");
    window.location.assign("/");
  } catch (_) {
    error.hidden = false;
    form.password.value = "";
    form.password.focus();
  } finally {
    button.disabled = false;
  }
});
