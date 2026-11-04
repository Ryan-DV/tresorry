(() => {
  "use strict";
  const $ = (s, el = document) => el.querySelector(s);
  const CSRF = $('meta[name="csrf"]').content;
  const body = document.body;
  const UPLOAD_URL = body.dataset.upload;
  const MKDIR_URL = body.dataset.mkdir;

  /* ---------- helpers ---------- */
  const human = (n) => {
    const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return i === 0 ? `${n} B` : `${n.toFixed(1)} ${u[i]}`;
  };
  let toastTimer;
  const toast = (msg) => {
    const t = $("#toast"); t.textContent = msg; t.hidden = false;
    clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.hidden = true), 2400);
  };

  /* ---------- filter ---------- */
  const filter = $("#filter");
  const applyFilter = () => {
    const q = filter.value.trim().toLowerCase();
    let shown = 0;
    document.querySelectorAll("#rows .row").forEach((r) => {
      const hit = !q || r.dataset.name.includes(q);
      r.hidden = !hit; if (hit) shown++;
    });
    const none = $("#none");
    const total = document.querySelectorAll("#rows .row").length;
    none.hidden = shown > 0;
    if (total && !shown) {
      none.querySelector("strong").textContent = "Nothing matches";
      none.querySelector(".muted").textContent = `No file in this folder contains "${filter.value}".`;
    }
  };
  filter.addEventListener("input", applyFilter);
  document.addEventListener("keydown", (e) => {
    if (e.key === "/" && document.activeElement.tagName !== "INPUT") { e.preventDefault(); filter.focus(); }
    if (e.key === "Escape" && document.activeElement === filter) { filter.value = ""; applyFilter(); filter.blur(); }
  });

  /* ---------- sort ---------- */
  let sortKey = "name", sortDir = 1;
  const fmt = new Intl.DateTimeFormat(undefined, { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
  const sortRows = () => {
    const rows = [...document.querySelectorAll("#rows .row")];
    rows.forEach((r) => { const d = r.querySelector(".col.date"); if (d && !d.dataset.local) { d.textContent = fmt.format(new Date(r.dataset.mtime * 1000)); d.dataset.local = 1; } });
    rows.sort((a, b) => {
      const d = b.dataset.dir - a.dataset.dir;
      if (d) return d;
      const ka = a.dataset[sortKey], kb = b.dataset[sortKey];
      const c = sortKey === "name" ? ka.localeCompare(kb, undefined, { numeric: true }) : ka - kb;
      return c * sortDir;
    });
    const host = $("#rows"); rows.forEach((r) => host.appendChild(r));
    document.querySelectorAll(".row.hdr [data-sort]").forEach((b) => {
      b.classList.toggle("on", b.dataset.sort === sortKey);
      b.classList.toggle("desc", b.dataset.sort === sortKey && sortDir < 0);
    });
  };
  document.querySelectorAll(".row.hdr [data-sort]").forEach((b) =>
    b.addEventListener("click", () => {
      if (sortKey === b.dataset.sort) sortDir = -sortDir;
      else { sortKey = b.dataset.sort; sortDir = sortKey === "name" ? 1 : -1; }
      sortRows();
    })
  );

  /* ---------- copy curl ---------- */
  document.addEventListener("click", async (e) => {
    const btn = e.target.closest(".copy");
    if (!btn) return;
    const url = `${location.origin}${btn.dataset.path}`;
    // POSIX single-quote escaping so a filename containing ' cannot break out in a shell
    const sq = (s) => `'${s.replace(/'/g, `'\\''`)}'`;
    const cmd = `curl -k -u :'PASSPHRASE' -OJ ${sq(url)}`;
    try { await navigator.clipboard.writeText(cmd); toast("curl command copied"); }
    catch { window.prompt("Copy this command", cmd); }
  });

  /* ---------- refresh listing without a reload ---------- */
  const refresh = async (highlight = []) => {
    const res = await fetch(location.pathname, { credentials: "same-origin", headers: { Accept: "text/html" } });
    if (!res.ok) return;
    const doc = new DOMParser().parseFromString(await res.text(), "text/html");
    $("#rows").replaceWith(doc.querySelector("#rows"));
    $("#meta").textContent = doc.querySelector("#meta").textContent;
    const none = $("#none"), fresh = doc.querySelector("#none");
    none.hidden = fresh.hidden; none.innerHTML = fresh.innerHTML;
    highlight.forEach((name) => {
      const row = [...document.querySelectorAll("#rows .row")].find((r) => r.dataset.name === name.toLowerCase());
      if (row) row.classList.add("fresh");
    });
    sortRows(); applyFilter();
  };

  /* ---------- uploads ---------- */
  const tray = $("#uploads"), list = $("#upList"), title = $("#upTitle");
  const queue = []; let active = 0, done = 0, failed = 0; const justSaved = [];
  const CONCURRENCY = 3;
  $("#upClose").addEventListener("click", () => (tray.hidden = true));

  const updateTitle = () => {
    const total = list.children.length;
    title.textContent = active || queue.length
      ? `Uploading ${done + failed + 1} of ${total}`
      : failed ? `${done} uploaded, ${failed} failed` : `${done} uploaded`;
  };

  const addFiles = (files) => {
    if (!files.length) return;
    tray.hidden = false;
    for (const f of files) {
      const li = document.createElement("li");
      li.innerHTML = `<div class="up-row"><span class="fn"></span><span class="up-pct">queued</span></div><div class="up-bar"><i></i></div>`;
      li.querySelector(".fn").textContent = f.name;
      list.prepend(li);
      queue.push({ f, li });
    }
    updateTitle(); pump();
  };

  const pump = () => {
    while (active < CONCURRENCY && queue.length) send(queue.shift());
  };

  const send = ({ f, li }) => {
    active++;
    const xhr = new XMLHttpRequest();
    const fd = new FormData(); fd.append("file", f, f.name);
    const pct = li.querySelector(".up-pct"), bar = li.querySelector(".up-bar i");
    const t0 = performance.now();
    xhr.upload.onprogress = (e) => {
      if (!e.lengthComputable) return;
      const p = (e.loaded / e.total) * 100;
      bar.style.width = `${p}%`;
      const rate = e.loaded / ((performance.now() - t0) / 1000);
      pct.textContent = `${p.toFixed(0)}% · ${human(rate)}/s`;
    };
    const finish = (ok, msg) => {
      active--; ok ? done++ : failed++;
      li.classList.add(ok ? "done" : "fail");
      pct.textContent = msg;
      updateTitle(); pump();
      if (!active && !queue.length) {
        refresh(justSaved.splice(0));
        if (!failed) setTimeout(() => { if (!active && !queue.length) tray.hidden = true; }, 4000);
      }
    };
    xhr.onload = () => {
      let data = {}; try { data = JSON.parse(xhr.responseText); } catch {}
      if (xhr.status === 200 && data.saved) {
        bar.style.width = "100%";
        data.saved.forEach((s) => justSaved.push(s.name));
        const renamed = data.saved[0] && data.saved[0].name !== f.name;
        if (renamed) { const s = document.createElement("div"); s.className = "up-sub"; s.textContent = `saved as ${data.saved[0].name}`; li.appendChild(s); }
        finish(true, human(f.size));
      } else if (xhr.status === 401) {
        finish(false, "session expired"); location.href = "/login";
      } else {
        finish(false, data.error || `error ${xhr.status}`);
      }
    };
    xhr.onerror = () => finish(false, "network error");
    xhr.open("POST", UPLOAD_URL);
    xhr.setRequestHeader("X-CSRF-Token", CSRF);
    xhr.send(fd);
  };

  $("#picker").addEventListener("change", (e) => { addFiles([...e.target.files]); e.target.value = ""; });

  /* drag and drop, anywhere on the page */
  const overlay = $("#overlay"); let depth = 0;
  const hasFiles = (e) => e.dataTransfer && [...e.dataTransfer.types].includes("Files");
  window.addEventListener("dragenter", (e) => { if (!hasFiles(e)) return; e.preventDefault(); depth++; overlay.hidden = false; });
  window.addEventListener("dragover", (e) => { if (hasFiles(e)) e.preventDefault(); });
  window.addEventListener("dragleave", (e) => { if (!hasFiles(e)) return; depth = Math.max(0, depth - 1); if (!depth) overlay.hidden = true; });
  window.addEventListener("drop", (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault(); depth = 0; overlay.hidden = true;
    const items = [...(e.dataTransfer.items || [])];
    const dirs = items.filter((it) => it.webkitGetAsEntry && it.webkitGetAsEntry()?.isDirectory);
    if (dirs.length) toast("Folders are skipped. Drop the files inside, or zip the folder.");
    addFiles([...e.dataTransfer.files].filter((f, i) => !(items[i] && items[i].webkitGetAsEntry && items[i].webkitGetAsEntry()?.isDirectory)));
  });
  /* paste files from clipboard */
  window.addEventListener("paste", (e) => {
    const files = [...(e.clipboardData?.files || [])];
    if (files.length) { e.preventDefault(); addFiles(files); }
  });

  /* ---------- new folder ---------- */
  const dlg = $("#mk"), mkName = $("#mkName"), mkErr = $("#mkErr");
  $("#newFolder").addEventListener("click", () => { mkErr.hidden = true; mkName.value = ""; dlg.showModal(); mkName.focus(); });
  $("#mkCancel").addEventListener("click", () => dlg.close());
  $("#mkForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = mkName.value.trim(); if (!name) return;
    const res = await fetch(MKDIR_URL, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF },
      body: JSON.stringify({ name }),
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) { dlg.close(); toast(`Folder "${name}" created`); refresh([name]); }
    else { mkErr.textContent = data.error || `Error ${res.status}`; mkErr.hidden = false; }
  });

  sortRows();
})();
