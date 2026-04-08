const loginOverlay = document.getElementById("loginOverlay");
const appContainer = document.getElementById("appContainer");
const loginForm = document.getElementById("loginForm");
const logoutBtn = document.getElementById("logoutBtn");
const loginStatusEl = document.getElementById("loginStatus");
const statusEl = document.getElementById("status");
const usersBody = document.getElementById("usersTableBody");
const createForm = document.getElementById("createUserForm");
const usersTabBtn = document.getElementById("usersTabBtn");
const analyticsTabBtn = document.getElementById("analyticsTabBtn");
const usersSection = document.getElementById("usersSection");
const usersTableSection = document.getElementById("usersTableSection");
const analyticsSection = document.getElementById("analyticsSection");
const archiveMenuBtn = document.getElementById("archiveMenuBtn");
const archiveMenu = document.getElementById("archiveMenu");
const backupBtn = document.getElementById("backupBtn");
const restoreInput = document.getElementById("restoreInput");
const chartUserSelect = document.getElementById("chartUserSelect");
const chartRangeSelect = document.getElementById("chartRangeSelect");
const chartRefreshBtn = document.getElementById("chartRefreshBtn");
const trafficChartCanvas = document.getElementById("trafficChart");
const statIn = document.getElementById("statIn");
const statOut = document.getElementById("statOut");
const statTotal = document.getElementById("statTotal");
const tgHostLabel = document.getElementById("tgHostLabel");
const httpCredsModal = document.getElementById("httpCredsModal");
const httpUserValue = document.getElementById("httpUserValue");
const httpPassValue = document.getElementById("httpPassValue");
const httpUrlValue = document.getElementById("httpUrlValue");
const copyHttpCredsBtn = document.getElementById("copyHttpCredsBtn");
const closeHttpCredsBtn = document.getElementById("closeHttpCredsBtn");

let panelMeta = {
  proxy_public_host: "127.0.0.1",
  proxy_public_mtproto_host: "127.0.0.1",
  proxy_public_http_port: 13128,
  proxy_public_socks_port: 11080,
  proxy_public_mtproto_port: 2053,
};
let currentHttpCredsText = "";
let usersCache = [];
const USERS_REFRESH_INTERVAL_MS = 5000;
let usersRefreshInFlight = false;
let trafficChart = null;

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

function showUsersTab() {
  usersSection.classList.remove("hidden");
  usersTableSection.classList.remove("hidden");
  analyticsSection.classList.add("hidden");
  usersTabBtn.classList.add("btn-primary");
  analyticsTabBtn.classList.remove("btn-primary");
}

function showAnalyticsTab() {
  usersSection.classList.add("hidden");
  usersTableSection.classList.add("hidden");
  analyticsSection.classList.remove("hidden");
  analyticsTabBtn.classList.add("btn-primary");
  usersTabBtn.classList.remove("btn-primary");
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

function metricStats(arr) {
  if (!arr.length) return { min: 0, max: 0, avg: 0 };
  const min = Math.min(...arr);
  const max = Math.max(...arr);
  const avg = arr.reduce((a, b) => a + b, 0) / arr.length;
  return { min, max, avg };
}

function formatRate(bytesPerSecond) {
  return `${formatBytes(bytesPerSecond)}/s`;
}

async function copyToClipboard(text) {
  if (!text) return false;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (_err) {
      // Fallback below for non-secure contexts/browser restrictions.
    }
  }
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  area.style.pointerEvents = "none";
  document.body.appendChild(area);
  area.focus();
  area.select();
  let copied = false;
  try {
    copied = document.execCommand("copy");
  } catch (_err) {
    copied = false;
  }
  document.body.removeChild(area);
  return copied;
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
  const mtprotoLink = `tg://proxy?server=${encodeURIComponent(panelMeta.proxy_public_mtproto_host || panelMeta.proxy_public_host)}&port=${encodeURIComponent(String(panelMeta.proxy_public_mtproto_port || 14443))}&secret=${encodeURIComponent(user.mtproto_secret || "")}`;
  tr.innerHTML = `
    <td>${user.id}</td>
    <td>${user.username}</td>
    <td>${user.allow_http ? "yes" : "no"}</td>
    <td>${user.allow_socks5 ? "yes" : "no"}</td>
    <td>${user.allow_mtproto ? "yes" : "no"}</td>
    <td>${formatBytes(user.traffic_in_bytes)}</td>
    <td>${formatBytes(user.traffic_out_bytes)}</td>
    <td>${formatBytes(user.traffic_bytes)}</td>
    <td>${user.requests_count}</td>
    <td>
      <div class="row-actions">
        <button class="btn btn-compact" data-action="toggle-http">${user.allow_http ? "HTTP off" : "HTTP on"}</button>
        <button class="btn btn-compact" data-action="toggle-socks">${user.allow_socks5 ? "SOCKS off" : "SOCKS on"}</button>
        <button class="btn btn-compact" data-action="toggle-mtproto">${user.allow_mtproto ? "MTProto off" : "MTProto on"}</button>
        <button class="btn btn-compact" data-action="http-creds">HTTP</button>
        <button class="btn btn-copy btn-compact" data-action="copy-socks">TG SOCKS5</button>
        <button class="btn btn-copy btn-compact" data-action="copy-mtproto">TG MTProto</button>
        <button class="btn btn-danger btn-compact" data-action="delete">Удалить</button>
      </div>
    </td>
  `;

  tr.querySelector('[data-action="toggle-http"]').addEventListener("click", async () => {
    await updateUser(user.id, { allow_http: !user.allow_http });
  });
  tr.querySelector('[data-action="toggle-socks"]').addEventListener("click", async () => {
    await updateUser(user.id, { allow_socks5: !user.allow_socks5 });
  });
  tr.querySelector('[data-action="toggle-mtproto"]').addEventListener("click", async () => {
    await updateUser(user.id, { allow_mtproto: !user.allow_mtproto });
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
    const copied = await copyToClipboard(tgLink);
    if (copied) {
      setStatus(`SOCKS5 ссылка скопирована для ${user.username}`);
    } else {
      setStatus(`Скопируйте вручную: ${tgLink}`, true);
    }
  });
  tr.querySelector('[data-action="copy-mtproto"]').addEventListener("click", async () => {
    if (!user.allow_mtproto || !user.mtproto_secret) {
      setStatus("У пользователя выключен MTProto", true);
      return;
    }
    const copied = await copyToClipboard(mtprotoLink);
    if (copied) {
      setStatus(`MTProto ссылка скопирована для ${user.username}`);
    } else {
      setStatus(`Скопируйте вручную: ${mtprotoLink}`, true);
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
    usersCache = users;
    usersBody.innerHTML = "";
    users.forEach((u) => usersBody.appendChild(userRow(u)));
    refreshChartUserOptions(users);
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

function refreshChartUserOptions(users) {
  const prev = chartUserSelect.value;
  chartUserSelect.innerHTML = "";
  const allOption = document.createElement("option");
  allOption.value = "";
  allOption.textContent = "Все пользователи";
  chartUserSelect.appendChild(allOption);
  users.forEach((u) => {
    const option = document.createElement("option");
    option.value = String(u.id);
    option.textContent = u.username;
    chartUserSelect.appendChild(option);
  });
  chartUserSelect.value = users.some((u) => String(u.id) === prev) ? prev : "";
}

async function loadTrafficChart() {
  const minutes = Number(chartRangeSelect.value || 180);
  const userId = chartUserSelect.value;
  const url = userId
    ? `/api/traffic/samples?user_id=${encodeURIComponent(userId)}&minutes=${minutes}`
    : `/api/traffic/samples?minutes=${minutes}`;
  const points = await api(url);
  if (!Array.isArray(points) || points.length < 2) {
    if (trafficChart) {
      trafficChart.destroy();
      trafficChart = null;
    }
    statIn.textContent = "IN min/max/avg: -";
    statOut.textContent = "OUT min/max/avg: -";
    statTotal.textContent = "TOTAL min/max/avg: -";
    return;
  }

  // Zabbix-like view: draw utilization rate (delta per second), not absolute counters.
  const labels = [];
  const inData = [];
  const outData = [];
  const totalData = [];
  for (let i = 1; i < points.length; i += 1) {
    const prev = points[i - 1];
    const curr = points[i];
    const prevTs = new Date(prev.captured_at).getTime();
    const currTs = new Date(curr.captured_at).getTime();
    const dtSec = Math.max(1, Math.round((currTs - prevTs) / 1000));

    const deltaIn = Math.max(0, Number(curr.traffic_in_bytes) - Number(prev.traffic_in_bytes));
    const deltaOut = Math.max(0, Number(curr.traffic_out_bytes) - Number(prev.traffic_out_bytes));
    const deltaTotal = Math.max(0, Number(curr.traffic_bytes) - Number(prev.traffic_bytes));

    labels.push(new Date(curr.captured_at).toLocaleTimeString());
    inData.push(deltaIn / dtSec);
    outData.push(deltaOut / dtSec);
    totalData.push(deltaTotal / dtSec);
  }

  const inStats = metricStats(inData);
  const outStats = metricStats(outData);
  const totalStats = metricStats(totalData);
  statIn.textContent = `IN min/max/avg: ${formatRate(inStats.min)} / ${formatRate(inStats.max)} / ${formatRate(inStats.avg)}`;
  statOut.textContent = `OUT min/max/avg: ${formatRate(outStats.min)} / ${formatRate(outStats.max)} / ${formatRate(outStats.avg)}`;
  statTotal.textContent = `TOTAL min/max/avg: ${formatRate(totalStats.min)} / ${formatRate(totalStats.max)} / ${formatRate(totalStats.avg)}`;

  if (trafficChart) {
    trafficChart.destroy();
  }
  trafficChart = new Chart(trafficChartCanvas, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Входящий",
          data: inData,
          borderColor: "#4f7cff",
          backgroundColor: "rgba(79,124,255,0.18)",
          fill: true,
          pointRadius: 0,
          borderWidth: 2,
          tension: 0.18,
        },
        {
          label: "Исходящий",
          data: outData,
          borderColor: "#22c55e",
          backgroundColor: "rgba(34,197,94,0.14)",
          fill: true,
          pointRadius: 0,
          borderWidth: 2,
          tension: 0.18,
        },
        {
          label: "Всего",
          data: totalData,
          borderColor: "#f59e0b",
          backgroundColor: "rgba(245,158,11,0.12)",
          fill: false,
          pointRadius: 0,
          borderWidth: 2,
          tension: 0.1,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {
        mode: "index",
        intersect: false,
      },
      plugins: {
        legend: {
          labels: { color: "#cfe0ff" },
        },
      },
      scales: {
        x: {
          grid: { color: "rgba(120,150,220,0.12)" },
          ticks: { color: "#a9bde9", maxRotation: 0, autoSkip: true, maxTicksLimit: 10 },
        },
        y: {
          grid: { color: "rgba(120,150,220,0.12)" },
          ticks: {
            color: "#a9bde9",
            callback(value) {
              return formatRate(Number(value));
            },
          },
          beginAtZero: true,
        },
      },
    },
  });
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
    allow_mtproto: formData.get("allow_mtproto") === "on",
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
    createForm.querySelector('input[name="allow_mtproto"]').checked = false;
    await loadUsers();
    await loadTrafficChart();
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
usersTabBtn.addEventListener("click", showUsersTab);
analyticsTabBtn.addEventListener("click", async () => {
  showAnalyticsTab();
  try {
    await loadTrafficChart();
  } catch (e) {
    setStatus(`Ошибка графика: ${e.message}`, true);
  }
});
chartRefreshBtn.addEventListener("click", async () => {
  try {
    await loadTrafficChart();
  } catch (e) {
    setStatus(`Ошибка графика: ${e.message}`, true);
  }
});
chartUserSelect.addEventListener("change", async () => {
  try {
    await loadTrafficChart();
  } catch (e) {
    setStatus(`Ошибка графика: ${e.message}`, true);
  }
});
chartRangeSelect.addEventListener("change", async () => {
  try {
    await loadTrafficChart();
  } catch (e) {
    setStatus(`Ошибка графика: ${e.message}`, true);
  }
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
    showUsersTab();
    await loadMeta();
    await loadUsers();
    await loadTrafficChart();
  } catch (_e) {
    showLoggedOutUI();
  }
  setInterval(async () => {
    if (!appContainer.classList.contains("hidden") && !document.hidden) {
      await loadUsers();
      if (!analyticsSection.classList.contains("hidden")) {
        await loadTrafficChart();
      }
    }
  }, USERS_REFRESH_INTERVAL_MS);
}

bootstrap();

copyHttpCredsBtn.addEventListener("click", async () => {
  if (!currentHttpCredsText) return;
  const copied = await copyToClipboard(currentHttpCredsText);
  if (copied) {
    setStatus("HTTP данные скопированы");
  } else {
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
