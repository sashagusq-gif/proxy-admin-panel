const loginOverlay = document.getElementById("loginOverlay");
const appContainer = document.getElementById("appContainer");
const loginForm = document.getElementById("loginForm");
const logoutBtn = document.getElementById("logoutBtn");
const loginStatusEl = document.getElementById("loginStatus");
const statusEl = document.getElementById("status");
const usersBody = document.getElementById("usersTableBody");
const createForm = document.getElementById("createUserForm");
const archiveMenuBtn = document.getElementById("archiveMenuBtn");
const archiveMenu = document.getElementById("archiveMenu");
const backupBtn = document.getElementById("backupBtn");
const restoreInput = document.getElementById("restoreInput");
const tgHostLabel = document.getElementById("tgHostLabel");
const httpCredsModal = document.getElementById("httpCredsModal");
const httpUserValue = document.getElementById("httpUserValue");
const httpPassValue = document.getElementById("httpPassValue");
const httpUrlValue = document.getElementById("httpUrlValue");
const copyHttpCredsBtn = document.getElementById("copyHttpCredsBtn");
const closeHttpCredsBtn = document.getElementById("closeHttpCredsBtn");

let panelMeta = {
  proxy_public_host: "127.0.0.1",
  proxy_public_http_port: 13128,
  proxy_public_socks_port: 11080,
};
let currentHttpCredsText = "";
const USERS_REFRESH_INTERVAL_MS = 5000;
let usersRefreshInFlight = false;

function openHttpCredsModal() {
  httpCredsModal.classList.remove("hidden");
  httpCredsModal.style.display = "flex";
}

function closeHttpCredsModal() {
  httpCredsModal.classList.add("hidden");
  httpCredsModal.style.display = "none";
}

function closeArchiveMenu() {
  archiveMenu.classList.add("hidden");
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(2)} KB`;
  const mb = kb / 1024;
  if (mb < 1024) return `${mb.toFixed(2)} MB`;
  return `${(mb / 1024).toFixed(2)} GB`;
}

function setStatus(msg, isError = false) {
  statusEl.textContent = msg;
  statusEl.style.color = isError ? "#fb7185" : "#4ade80";
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const data = await response.json();
      detail = data.detail || detail;
    } catch (_e) {}
    throw new Error(detail);
  }
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return response.json();
  }
  return response;
}

function userRow(user) {
  const tr = document.createElement("tr");
  const tgLink = `tg://socks?server=${encodeURIComponent(panelMeta.proxy_public_host)}&port=${encodeURIComponent(String(panelMeta.proxy_public_socks_port))}&user=${encodeURIComponent(user.username)}&pass=${encodeURIComponent(user.password || "")}`;
  tr.innerHTML = `
    <td>${user.id}</td>
    <td>${user.username}</td>
    <td>${user.allow_http ? "yes" : "no"}</td>
    <td>${user.allow_socks5 ? "yes" : "no"}</td>
    <td>${formatBytes(user.traffic_in_bytes)}</td>
    <td>${formatBytes(user.traffic_out_bytes)}</td>
    <td>${formatBytes(user.traffic_bytes)}</td>
    <td>${user.requests_count}</td>
    <td>
      <button class="btn" data-action="toggle-http">${user.allow_http ? "HTTP off" : "HTTP on"}</button>
      <button class="btn" data-action="toggle-socks">${user.allow_socks5 ? "SOCKS off" : "SOCKS on"}</button>
      <button class="btn" data-action="http-creds">HTTP данные</button>
      <button class="btn btn-copy" data-action="copy-socks">Copy TG SOCKS5</button>
      <button class="btn btn-danger" data-action="delete">Удалить</button>
    </td>
  `;

  tr.querySelector('[data-action="toggle-http"]').addEventListener("click", async () => {
    await updateUser(user.id, { allow_http: !user.allow_http });
  });
  tr.querySelector('[data-action="toggle-socks"]').addEventListener("click", async () => {
    await updateUser(user.id, { allow_socks5: !user.allow_socks5 });
  });
  tr.querySelector('[data-action="delete"]').addEventListener("click", async () => {
    if (!confirm(`Удалить пользователя ${user.username}?`)) return;
    try {
      await api(`/api/users/${user.id}`, { method: "DELETE" });
      setStatus(`Пользователь ${user.username} удален`);
      await loadUsers();
    } catch (e) {
      setStatus(e.message, true);
    }
  });
  tr.querySelector('[data-action="copy-socks"]').addEventListener("click", async () => {
    if (!user.allow_socks5) {
      setStatus("У пользователя выключен SOCKS5", true);
      return;
    }
    try {
      await navigator.clipboard.writeText(tgLink);
      setStatus(`SOCKS5 ссылка скопирована для ${user.username}`);
    } catch (_e) {
      setStatus(`Скопируйте вручную: ${tgLink}`, true);
    }
  });
  tr.querySelector('[data-action="http-creds"]').addEventListener("click", () => {
    if (!user.allow_http) {
      setStatus("У пользователя выключен HTTP", true);
      return;
    }
    const host = panelMeta.proxy_public_host;
    const httpPort = panelMeta.proxy_public_http_port || 13128;
    const url = `http://${user.username}:${user.password}@${host}:${httpPort}`;
    httpUserValue.textContent = user.username;
    httpPassValue.textContent = user.password;
    httpUrlValue.textContent = url;
    currentHttpCredsText = `HTTP Proxy\nHost: ${host}\nPort: ${httpPort}\nUsername: ${user.username}\nPassword: ${user.password}\nURL: ${url}`;
    openHttpCredsModal();
  });
  return tr;
}

async function updateUser(id, payload) {
  try {
    await api(`/api/users/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setStatus("Пользователь обновлен");
    await loadUsers();
  } catch (e) {
    setStatus(e.message, true);
  }
}

async function loadUsers() {
  if (usersRefreshInFlight) return;
  usersRefreshInFlight = true;
  try {
    const users = await api("/api/users");
    usersBody.innerHTML = "";
    users.forEach((u) => usersBody.appendChild(userRow(u)));
  } catch (e) {
    setStatus(`Ошибка загрузки: ${e.message}`, true);
  } finally {
    usersRefreshInFlight = false;
  }
}

async function loadMeta() {
  panelMeta = await api("/api/meta");
  tgHostLabel.textContent = `${panelMeta.proxy_public_host}:${panelMeta.proxy_public_socks_port}`;
}

function showLoggedInUI() {
  loginOverlay.classList.add("hidden");
  appContainer.classList.remove("hidden");
  loginStatusEl.textContent = "";
}

function showLoggedOutUI() {
  appContainer.classList.add("hidden");
  loginOverlay.classList.remove("hidden");
}

createForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const formData = new FormData(createForm);
  const payload = {
    username: String(formData.get("username") || "").trim(),
    password: String(formData.get("password") || ""),
    allow_http: formData.get("allow_http") === "on",
    allow_socks5: formData.get("allow_socks5") === "on",
  };
  try {
    await api("/api/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setStatus(`Пользователь ${payload.username} создан`);
    createForm.reset();
    createForm.querySelector('input[name="allow_http"]').checked = true;
    createForm.querySelector('input[name="allow_socks5"]').checked = true;
    await loadUsers();
  } catch (err) {
    setStatus(err.message, true);
  }
});

logoutBtn.addEventListener("click", async () => {
  try {
    await api("/api/auth/logout", { method: "POST" });
  } catch (_e) {}
  showLoggedOutUI();
  setStatus("");
});

backupBtn.addEventListener("click", async () => {
  try {
    const response = await fetch("/api/backup", { method: "POST" });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const blob = await response.blob();
    const cd = response.headers.get("content-disposition") || "";
    const nameMatch = /filename="?([^"]+)"?/.exec(cd);
    const filename = nameMatch ? nameMatch[1] : "proxy-users-backup.json";
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
    setStatus("Backup успешно выгружен");
    closeArchiveMenu();
  } catch (err) {
    setStatus(`Ошибка backup: ${err.message}`, true);
  }
});

restoreInput.addEventListener("change", async () => {
  const file = restoreInput.files?.[0];
  if (!file) return;
  const fd = new FormData();
  fd.append("file", file);
  try {
    await api("/api/restore", { method: "POST", body: fd });
    setStatus("Восстановление выполнено");
    await loadUsers();
    closeArchiveMenu();
  } catch (err) {
    setStatus(`Ошибка восстановления: ${err.message}`, true);
  } finally {
    restoreInput.value = "";
  }
});

archiveMenuBtn.addEventListener("click", () => {
  archiveMenu.classList.toggle("hidden");
});

loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const formData = new FormData(loginForm);
  const payload = {
    username: String(formData.get("username") || "").trim(),
    password: String(formData.get("password") || ""),
  };
  try {
    await api("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    showLoggedInUI();
    await loadMeta();
    await loadUsers();
    setStatus("Вы успешно вошли");
  } catch (e1) {
    loginStatusEl.textContent = `Ошибка входа: ${e1.message}`;
  }
});

async function bootstrap() {
  try {
    await api("/api/auth/me");
    showLoggedInUI();
    await loadMeta();
    await loadUsers();
  } catch (_e) {
    showLoggedOutUI();
  }
  setInterval(async () => {
    if (!appContainer.classList.contains("hidden") && !document.hidden) {
      await loadUsers();
    }
  }, USERS_REFRESH_INTERVAL_MS);
}

bootstrap();

copyHttpCredsBtn.addEventListener("click", async () => {
  if (!currentHttpCredsText) return;
  try {
    await navigator.clipboard.writeText(currentHttpCredsText);
    setStatus("HTTP данные скопированы");
  } catch (_e) {
    setStatus("Не удалось скопировать, скопируйте вручную", true);
  }
});

closeHttpCredsBtn.addEventListener("click", closeHttpCredsModal);

httpCredsModal.addEventListener("click", (event) => {
  if (event.target === httpCredsModal) {
    closeHttpCredsModal();
  }
});

document.addEventListener("click", (event) => {
  if (!archiveMenu.contains(event.target) && event.target !== archiveMenuBtn) {
    closeArchiveMenu();
  }
});
