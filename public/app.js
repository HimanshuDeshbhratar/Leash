(() => {
  const $ = (sel) => document.querySelector(sel);

  const issueForm = $("#issue-form");
  const executeForm = $("#execute-form");
  const revokeForm = $("#revoke-form");

  let lastSeenTopId = null;

  function show(el) {
    el.classList.remove("hidden");
  }

  function hide(el) {
    el.classList.add("hidden");
  }

  function setError(el, msg) {
    el.textContent = msg;
    show(el);
  }

  async function post(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
  }

  // --- Issue ---
  issueForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    hide($("#issue-error"));
    hide($("#issue-result"));

    const fd = new FormData(issueForm);
    const { ok, data } = await post("/request-token", {
      principal: fd.get("principal"),
      scope: fd.get("scope"),
      ttl_seconds: Number(fd.get("ttl_seconds")),
    });

    if (!ok) {
      setError($("#issue-error"), JSON.stringify(data, null, 2));
      return;
    }

    $("#issued-token-id").textContent = data.token_id;
    $("#issued-expires").textContent = data.expires_at_iso;
    $("#issued-token").textContent = data.token;
    $("#issued-token").dataset.full = data.token;
    show($("#issue-result"));

    // Convenience: prefill execute + revoke forms
    executeForm.token.value = data.token;
    executeForm.action.value = data.scope;
    revokeForm.token_id.value = data.token_id;
  });

  $("#copy-token").addEventListener("click", async () => {
    const full = $("#issued-token").dataset.full || $("#issued-token").textContent;
    try {
      await navigator.clipboard.writeText(full);
      const btn = $("#copy-token");
      btn.textContent = "copied";
      setTimeout(() => {
        btn.textContent = "copy";
      }, 1200);
    } catch {
      /* clipboard may be blocked; ignore */
    }
  });

  // --- Execute ---
  executeForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    hide($("#execute-error"));
    hide($("#execute-result"));

    const fd = new FormData(executeForm);
    const { ok, data } = await post("/execute", {
      token: fd.get("token"),
      action: fd.get("action"),
    });

    if (!ok) {
      setError($("#execute-error"), JSON.stringify(data, null, 2));
      return;
    }

    const el = $("#execute-result");
    el.textContent = JSON.stringify(data, null, 2);
    show(el);
  });

  // --- Revoke ---
  revokeForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    hide($("#revoke-error"));
    hide($("#revoke-result"));

    const fd = new FormData(revokeForm);
    const { ok, data } = await post("/revoke", {
      token_id: fd.get("token_id"),
      principal: fd.get("principal"),
    });

    if (!ok) {
      setError($("#revoke-error"), JSON.stringify(data, null, 2));
      return;
    }

    const el = $("#revoke-result");
    el.textContent = JSON.stringify(data, null, 2);
    show(el);
  });

  // --- Audit log polling ---
  function formatTime(unix) {
    const d = new Date(unix * 1000);
    return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
  }

  function shortId(id) {
    if (!id) return "—";
    return id.length > 12 ? id.slice(0, 8) + "…" : id;
  }

  function renderAudit(entries) {
    const tbody = $("#audit-body");

    if (!entries.length) {
      tbody.innerHTML = `<tr class="empty"><td colspan="7">no entries yet</td></tr>`;
      lastSeenTopId = null;
      return;
    }

    const topId = entries[0].id;
    const isNew = lastSeenTopId !== null && topId !== lastSeenTopId;

    tbody.innerHTML = entries
      .map((row, i) => {
        const flash = isNew && i === 0 ? " flash" : "";
        const decisionClass =
          row.decision === "allowed" ? "decision-allowed" : "decision-denied";
        return `<tr class="${flash}">
          <td title="${formatTime(row.timestamp)}">${formatTime(row.timestamp)}</td>
          <td>${esc(row.action)}</td>
          <td class="${decisionClass}">${esc(row.decision)}</td>
          <td title="${esc(row.reason)}">${esc(row.reason)}</td>
          <td title="${esc(row.scope || "")}">${esc(row.scope || "—")}</td>
          <td>${esc(row.principal || "—")}</td>
          <td title="${esc(row.token_id || "")}">${esc(shortId(row.token_id))}</td>
        </tr>`;
      })
      .join("");

    lastSeenTopId = topId;
  }

  function esc(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  async function pollAudit() {
    try {
      const res = await fetch("/audit-log?limit=40&offset=0");
      if (!res.ok) return;
      const data = await res.json();
      renderAudit(data.entries || []);
      $("#audit-meta").textContent = `${data.total} entries · polling every 2s`;
    } catch {
      $("#audit-meta").textContent = "poll failed · retrying…";
    }
  }

  pollAudit();
  setInterval(pollAudit, 2000);
})();
