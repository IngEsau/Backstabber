const state = {
  engagements: [],
  jobs: [],
  approvals: [],
  audit: [],
  overview: {}
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "content-type": "application/json" },
    ...options
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || response.statusText);
  }
  return payload;
}

function setStatus(message) {
  document.querySelector("#status").textContent = message;
}

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

function text(value) {
  return value === undefined || value === null || value === "" ? "-" : String(value);
}

function renderOverview() {
  const counts = state.overview.counts || {};
  const metrics = [
    ["Engagements", counts.engagements || 0],
    ["Assets", counts.assets || 0],
    ["Jobs", counts.jobs || 0],
    ["Approvals", counts.approvals || 0],
    ["Executions", counts.executions || 0]
  ];
  document.querySelector("#overview").innerHTML = metrics.map(([label, value]) => `
    <article class="metric">
      <strong>${value}</strong>
      <span>${label}</span>
    </article>
  `).join("");
}

function renderEngagements() {
  const list = document.querySelector("#engagement-list");
  list.innerHTML = state.engagements.map((item) => `
    <article class="item">
      <header>
        <strong>${item.name}</strong>
        <span class="badge ${item.status}">${item.status}</span>
      </header>
      <p>${item.scope_cidrs.join(", ")}</p>
      <small>${item.id}</small>
    </article>
  `).join("") || `<p>No engagements registered.</p>`;

  for (const selector of ["#asset-form select[name='engagement']", "#job-form select[name='engagement']"]) {
    const select = document.querySelector(selector);
    select.innerHTML = state.engagements.map((item) => (
      `<option value="${item.id}">${item.name}</option>`
    )).join("");
  }
}

function renderJobs() {
  const tbody = document.querySelector("#jobs-body");
  tbody.innerHTML = state.jobs.map((job) => `
    <tr>
      <td>${text(job.created_at)}</td>
      <td>${job.operation}</td>
      <td><span class="badge ${job.status}">${job.status}</span></td>
      <td>${text(job.payload.target || job.payload.target_ip || job.payload.iface)}</td>
      <td>${text(job.last_error)}</td>
    </tr>
  `).join("") || `<tr><td colspan="5">No jobs queued.</td></tr>`;
}

function renderApprovals() {
  const list = document.querySelector("#approval-list");
  list.innerHTML = state.approvals.map((approval) => `
    <article class="item">
      <header>
        <strong>${approval.action}</strong>
        <span class="badge ${approval.status}">${approval.status}</span>
      </header>
      <p>${approval.reason}</p>
      <small>${approval.id}</small>
      ${approval.status === "pending" ? `
        <div class="actions">
          <button data-approve="${approval.id}" type="button">Approve</button>
          <button data-reject="${approval.id}" type="button">Reject</button>
        </div>
      ` : ""}
    </article>
  `).join("") || `<p>No approvals pending.</p>`;
}

function renderAudit() {
  const list = document.querySelector("#audit-list");
  list.innerHTML = state.audit.map((entry) => `
    <article class="item">
      <header>
        <strong>${entry.action}</strong>
        <span class="badge">${entry.actor}</span>
      </header>
      <p>${entry.entity_type}: ${entry.entity_id}</p>
      <small>${entry.ts}</small>
    </article>
  `).join("") || `<p>No audit events.</p>`;
}

async function refresh() {
  setStatus("Refreshing...");
  const [overview, engagements, jobs, approvals, audit] = await Promise.all([
    api("/api/overview"),
    api("/api/engagements"),
    api("/api/jobs"),
    api("/api/approvals"),
    api("/api/audit?limit=30")
  ]);
  Object.assign(state, { overview, engagements, jobs, approvals, audit });
  renderOverview();
  renderEngagements();
  renderJobs();
  renderApprovals();
  renderAudit();
  setStatus("Connected");
}

function formObject(form) {
  return Object.fromEntries(new FormData(form).entries());
}

document.querySelector("#refresh").addEventListener("click", () => {
  refresh().catch((error) => setStatus(error.message));
});

document.querySelector("#engagement-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = formObject(form);
  await api("/api/engagements", {
    method: "POST",
    body: JSON.stringify({
      actor: "dashboard",
      name: data.name,
      description: data.description || "",
      scope_cidrs: data.scope.split(",").map((item) => item.trim()).filter(Boolean),
      approval_required: Boolean(data.approval_required)
    })
  });
  form.reset();
  form.querySelector("input[name='approval_required']").checked = true;
  await refresh();
});

document.querySelector("#asset-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = formObject(form);
  await api(`/api/engagements/${encodeURIComponent(data.engagement)}/assets`, {
    method: "POST",
    body: JSON.stringify({
      actor: "dashboard",
      address: data.address,
      hostname: data.hostname,
      tags: (data.tags || "").split(",").map((item) => item.trim()).filter(Boolean)
    })
  });
  form.reset();
  await refresh();
});

document.querySelector("#job-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const submitter = event.submitter;
  const form = event.currentTarget;
  const data = formObject(form);
  const body = {
    actor: "dashboard",
    engagement_id: data.engagement,
    operation: "network.scan",
    payload: {
      target: data.target,
      ports: data.ports,
      iface: data.iface
    }
  };
  const result = await api(submitter.value === "dry-run" ? "/api/jobs/dry-run" : "/api/jobs", {
    method: "POST",
    body: JSON.stringify(body)
  });
  document.querySelector("#plan-output").textContent = pretty(result.plan || result);
  if (submitter.value === "enqueue") {
    await refresh();
  }
});

document.querySelector("#approval-list").addEventListener("click", async (event) => {
  const approve = event.target.closest("[data-approve]");
  const reject = event.target.closest("[data-reject]");
  if (!approve && !reject) {
    return;
  }
  const id = approve ? approve.dataset.approve : reject.dataset.reject;
  const action = approve ? "approve" : "reject";
  await api(`/api/approvals/${encodeURIComponent(id)}/${action}`, {
    method: "POST",
    body: JSON.stringify({ actor: "dashboard" })
  });
  await refresh();
});

refresh().catch((error) => setStatus(error.message));
