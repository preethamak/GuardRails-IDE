const tree = document.querySelector("#file-tree");
const nameNode = document.querySelector("#workspace-name");
const welcome = document.querySelector("#welcome");
const editor = document.querySelector("#editor");
const code = document.querySelector("#code");
const tab = document.querySelector("#active-tab");
const auditList = document.querySelector("#audit-list");

async function json(url) {
  const response = await fetch(url, { headers: { Accept: "application/json" } });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}

function icon(path) {
  if (path.endsWith(".rs")) return "RS";
  if (path.endsWith(".md")) return "MD";
  if (path.endsWith(".toml")) return "T";
  if (path.endsWith(".json")) return "{}";
  return "·";
}

function renderFiles(files) {
  tree.replaceChildren();
  for (const path of files) {
    const button = document.createElement("button");
    button.className = "file";
    button.innerHTML = `<span class="file-icon">${icon(path)}</span><span></span>`;
    button.lastElementChild.textContent = path;
    button.addEventListener("click", () => openFile(path, button));
    tree.append(button);
  }
}

async function openFile(path, button) {
  document.querySelectorAll(".file.active").forEach((item) => item.classList.remove("active"));
  button.classList.add("active");
  tab.textContent = path;
  try {
    const file = await json(`/api/file?path=${encodeURIComponent(path)}`);
    code.textContent = file.content;
    welcome.classList.add("hidden");
    editor.classList.remove("hidden");
    await refreshAudit();
  } catch (error) {
    code.textContent = `GuardRails blocked this request.\n\n${error.message}`;
    welcome.classList.add("hidden");
    editor.classList.remove("hidden");
  }
}

async function refreshAudit() {
  const events = await json("/api/audit");
  auditList.replaceChildren();
  for (const event of events.slice(-6).reverse()) {
    const row = document.createElement("div");
    row.className = "audit-row";
    row.innerHTML = `<span class="decision ${event.outcome}">${event.outcome}</span><code></code><span></span>`;
    row.children[1].textContent = event.resource;
    row.children[2].textContent = `${event.principal_id} · ${event.reason}`;
    auditList.append(row);
  }
}

json("/api/workspace")
  .then((workspace) => {
    nameNode.textContent = workspace.name.toUpperCase();
    renderFiles(workspace.files);
  })
  .catch((error) => { nameNode.textContent = error.message; });
