(() => {
  const CATEGORIES = JSON.parse(document.getElementById("catalog-data").textContent);
  const HOMEPAGES = JSON.parse(document.getElementById("homepages-data").textContent);
  const KEYS_STORAGE = "osint_dashboard_keys";

  const targetInput = document.getElementById("target");
  const typeSelect = document.getElementById("input-type");
  const main = document.getElementById("categories");

  const slugify = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");

  function loadKeys() {
    try {
      return JSON.parse(localStorage.getItem(KEYS_STORAGE) || "{}");
    } catch {
      return {};
    }
  }

  function saveKeys(keys) {
    localStorage.setItem(KEYS_STORAGE, JSON.stringify(keys));
  }

  function uniqueKeyServices() {
    const seen = new Map();
    for (const cat of CATEGORIES) {
      for (const svc of cat.services) {
        if (svc.key_name && !seen.has(svc.key_name)) {
          seen.set(svc.key_name, svc.name);
        }
      }
    }
    return seen;
  }

  function buildKeysModal() {
    const fieldsWrap = document.querySelector("#keys-modal .key-fields");
    const keys = loadKeys();
    const keyServices = uniqueKeyServices();
    fieldsWrap.innerHTML = "";
    for (const [keyName, label] of keyServices) {
      const row = document.createElement("label");
      row.className = "key-row";
      row.innerHTML = `
        <span>${label}</span>
        <input type="password" data-key="${keyName}" value="${keys[keyName] || ""}" placeholder="API key">
      `;
      fieldsWrap.appendChild(row);
    }
  }

  const modal = document.getElementById("keys-modal");
  document.getElementById("keys-btn").addEventListener("click", () => {
    buildKeysModal();
    modal.showModal();
  });
  document.getElementById("keys-form").addEventListener("submit", (e) => {
    if (e.submitter && e.submitter.value === "save") {
      const keys = loadKeys();
      modal.querySelectorAll("input[data-key]").forEach((input) => {
        keys[input.dataset.key] = input.value.trim();
      });
      saveKeys(keys);
    }
  });

  function buildUrl(service, target) {
    if (!service.link) {
      return HOMEPAGES[service.name] || null;
    }
    const b64 = btoa(unescape(encodeURIComponent(target)));
    return service.link
      .replace(/\{target_b64\}/g, encodeURIComponent(b64))
      .replace(/\{target\}/g, encodeURIComponent(target));
  }

  function isCompatible(service, inputType) {
    return service.inputs.length === 0 || service.inputs.includes(inputType);
  }

  // ---------------------------------------------------------------------
  // Offline AI assistant
  // ---------------------------------------------------------------------
  const aiPanel = document.getElementById("ai-panel");
  const aiMessages = document.getElementById("ai-messages");
  const aiForm = document.getElementById("ai-form");
  const aiInput = document.getElementById("ai-input");

  function openAIPanel() {
    aiPanel.hidden = false;
  }

  document.getElementById("ai-btn").addEventListener("click", () => {
    aiPanel.hidden = !aiPanel.hidden;
  });
  document.getElementById("ai-close").addEventListener("click", () => {
    aiPanel.hidden = true;
  });

  function appendAIBubble(role, text) {
    const bubble = document.createElement("div");
    bubble.className = `ai-bubble ai-${role}`;
    bubble.textContent = text;
    aiMessages.appendChild(bubble);
    aiMessages.scrollTop = aiMessages.scrollHeight;
    return bubble;
  }

  async function askAI(message, { endpoint = "/api/ai/chat", extraBody = {} } = {}) {
    openAIPanel();
    appendAIBubble("user", message);
    const pending = appendAIBubble("assistant ai-pending", "Thinking…");
    try {
      const resp = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message, ...extraBody }),
      });
      const data = await resp.json();
      pending.classList.remove("ai-pending");
      if (!data.ok) {
        pending.classList.add("ai-error");
        pending.textContent = data.error || "The AI assistant failed to respond.";
        return;
      }
      pending.textContent = data.reply;
      if (data.sources && data.sources.length) {
        const src = document.createElement("div");
        src.className = "ai-sources";
        src.textContent = `Sources: ${data.sources.join(", ")}`;
        pending.appendChild(src);
      }
    } catch (err) {
      pending.classList.remove("ai-pending");
      pending.classList.add("ai-error");
      pending.textContent = `Request failed: ${err}`;
    }
  }

  aiForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const message = aiInput.value.trim();
    if (!message) return;
    aiInput.value = "";
    askAI(message);
  });

  function renderResult(panel, result, service) {
    panel.classList.remove("loading");
    panel.innerHTML = "";
    if (!result.ok) {
      const err = document.createElement("p");
      err.className = "result-error";
      err.textContent = result.error;
      panel.appendChild(err);
      return;
    }
    const list = document.createElement("dl");
    list.className = "result-list";
    for (const item of result.items) {
      const dt = document.createElement("dt");
      dt.textContent = item.label;
      const dd = document.createElement("dd");
      dd.textContent = item.value;
      list.appendChild(dt);
      list.appendChild(dd);
    }
    panel.appendChild(list);

    if (service) {
      const explainBtn = document.createElement("button");
      explainBtn.type = "button";
      explainBtn.className = "explain-btn";
      explainBtn.textContent = "Explain with AI";
      explainBtn.addEventListener("click", () => {
        askAI(`Explain these ${service.name} results.`, {
          endpoint: "/api/ai/explain",
          extraBody: { service: service.name, result },
        });
      });
      panel.appendChild(explainBtn);
    }
  }

  function makeCard(category, service) {
    const card = document.createElement("article");
    card.className = "card";
    const id = `${category.id}-${slugify(service.name)}`;
    card.id = id;

    const badges = service.inputs.length
      ? service.inputs.map((i) => `<span class="badge">${i}</span>`).join("")
      : `<span class="badge badge-muted">launcher</span>`;

    card.innerHTML = `
      <h3>${service.name}</h3>
      <p class="desc">${service.desc}</p>
      <div class="badges">${badges}${service.live ? '<span class="badge badge-live">live</span>' : ""}${service.key_name ? '<span class="badge badge-key">key</span>' : ""}</div>
      <div class="actions">
        <button class="open-btn" type="button">Open</button>
        ${service.live ? '<button class="run-btn" type="button">Run</button>' : ""}
      </div>
      ${service.live ? '<div class="result-panel"></div>' : ""}
    `;

    const openBtn = card.querySelector(".open-btn");
    openBtn.addEventListener("click", () => {
      const target = targetInput.value.trim();
      const inputType = typeSelect.value;
      if (service.inputs.length && !isCompatible(service, inputType)) {
        alert(`${service.name} supports: ${service.inputs.join(", ")}`);
        return;
      }
      if (service.link && !target) {
        alert("Enter a target first.");
        return;
      }
      const url = buildUrl(service, target);
      if (!url) {
        alert(`${service.name} has no direct link; search for it manually.`);
        return;
      }
      window.open(url, "_blank", "noopener,noreferrer");
    });

    if (service.live) {
      const runBtn = card.querySelector(".run-btn");
      const panel = card.querySelector(".result-panel");
      runBtn.addEventListener("click", async () => {
        const target = targetInput.value.trim();
        const inputType = typeSelect.value;
        if (!isCompatible(service, inputType)) {
          alert(`${service.name} supports: ${service.inputs.join(", ")}`);
          return;
        }
        if (!target) {
          alert("Enter a target first.");
          return;
        }
        const keys = loadKeys();
        panel.classList.add("loading");
        panel.innerHTML = "<p>Looking up&hellip;</p>";
        try {
          const resp = await fetch(`/api/lookup/${service.live}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              target,
              input_type: inputType,
              api_key: service.key_name ? keys[service.key_name] || "" : "",
            }),
          });
          const result = await resp.json();
          renderResult(panel, result, service);
        } catch (err) {
          renderResult(panel, { ok: false, error: `Request failed: ${err}` }, service);
        }
      });
    }

    return card;
  }

  function render() {
    main.innerHTML = "";
    for (const category of CATEGORIES) {
      const section = document.createElement("section");
      section.className = "category";
      const heading = document.createElement("h2");
      heading.textContent = category.title;
      section.appendChild(heading);
      const grid = document.createElement("div");
      grid.className = "grid";
      for (const service of category.services) {
        grid.appendChild(makeCard(category, service));
      }
      section.appendChild(grid);
      main.appendChild(section);
    }
  }

  // ---------------------------------------------------------------------
  // Relationship graph (domain -> IP -> port -> software -> CVE)
  // ---------------------------------------------------------------------
  const NODE_COLORS = {
    domain: "#5eb0ff",
    ip: "#38c977",
    port: "#2dd4bf",
    software: "#c084fc",
    cve: "#ff6b6b",
  };
  const NODE_RADIUS = { domain: 14, ip: 12, port: 8, software: 10, cve: 10 };

  const graphModal = document.getElementById("graph-modal");
  const graphSvg = document.getElementById("graph-svg");
  const graphStatus = document.getElementById("graph-status");
  const graphDomainInput = document.getElementById("graph-domain");

  document.getElementById("graph-btn").addEventListener("click", () => {
    const t = targetInput.value.trim();
    if (t && typeSelect.value === "domain") graphDomainInput.value = t;
    graphModal.showModal();
  });
  document.getElementById("graph-close").addEventListener("click", () => graphModal.close());

  // Simple Fruchterman-Reingold force-directed layout, run once up front
  // (no external graphing library — this has to keep working with no
  // internet access once the page itself is loaded).
  function layoutGraph(nodes, edges, width, height) {
    const k = Math.sqrt((width * height) / Math.max(nodes.length, 1)) * 0.9;
    // Distance floor and a hard force cap: without both, two nodes that
    // land very close during the simulation drive k*k/dist toward
    // Infinity, and Infinity/Infinity evaluates to NaN in JS — which then
    // spreads to every other node through the pairwise interactions.
    const minDist = 1;
    const maxForce = k * k * 4;
    const pos = new Map();
    nodes.forEach((n, i) => {
      const angle = (2 * Math.PI * i) / nodes.length;
      pos.set(n.id, {
        x: width / 2 + Math.cos(angle) * (width / 3),
        y: height / 2 + Math.sin(angle) * (height / 3),
      });
    });

    const iterations = 300;
    for (let iter = 0; iter < iterations; iter++) {
      const disp = new Map(nodes.map((n) => [n.id, { x: 0, y: 0 }]));

      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = pos.get(nodes[i].id);
          const b = pos.get(nodes[j].id);
          let dx = a.x - b.x, dy = a.y - b.y;
          const dist = Math.max(Math.sqrt(dx * dx + dy * dy), minDist);
          const force = Math.min((k * k) / dist, maxForce);
          dx = (dx / dist) * force;
          dy = (dy / dist) * force;
          disp.get(nodes[i].id).x += dx;
          disp.get(nodes[i].id).y += dy;
          disp.get(nodes[j].id).x -= dx;
          disp.get(nodes[j].id).y -= dy;
        }
      }

      // Accumulate into disp like repulsion does, instead of mutating pos
      // directly here — a node with several edges (common: a shared
      // software or CVE node) would otherwise have each edge's update
      // compound on the position the previous edge in this same pass just
      // wrote, unclamped, which runs away to Infinity within a handful of
      // edges and then poisons every other node through the next
      // iteration's repulsion pass (Infinity/Infinity = NaN in JS).
      for (const e of edges) {
        const a = pos.get(e.source);
        const b = pos.get(e.target);
        if (!a || !b) continue;
        let dx = a.x - b.x, dy = a.y - b.y;
        const dist = Math.max(Math.sqrt(dx * dx + dy * dy), minDist);
        const force = Math.min((dist * dist) / k, maxForce);
        dx = (dx / dist) * force;
        dy = (dy / dist) * force;
        disp.get(e.source).x -= dx;
        disp.get(e.source).y -= dy;
        disp.get(e.target).x += dx;
        disp.get(e.target).y += dy;
      }

      const temp = Math.max(width, height) * (1 - iter / iterations) * 0.05;
      for (const n of nodes) {
        const d = disp.get(n.id);
        const dist = Math.max(Math.sqrt(d.x * d.x + d.y * d.y), minDist);
        const p = pos.get(n.id);
        p.x += (d.x / dist) * Math.min(dist, temp);
        p.y += (d.y / dist) * Math.min(dist, temp);
        p.x += (width / 2 - p.x) * 0.002;
        p.y += (height / 2 - p.y) * 0.002;
        p.x = Math.max(24, Math.min(width - 24, p.x));
        p.y = Math.max(24, Math.min(height - 24, p.y));
      }
    }
    return pos;
  }

  function renderGraph(nodes, edges) {
    const wrap = document.getElementById("graph-canvas-wrap");
    const width = Math.max(wrap.clientWidth, 600);
    const height = Math.max(wrap.clientHeight, 500);
    graphSvg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    graphSvg.innerHTML = "";

    if (!nodes.length) return;
    const pos = layoutGraph(nodes, edges, width, height);

    const edgeGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");
    for (const e of edges) {
      const a = pos.get(e.source);
      const b = pos.get(e.target);
      if (!a || !b) continue;
      const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
      line.setAttribute("x1", a.x);
      line.setAttribute("y1", a.y);
      line.setAttribute("x2", b.x);
      line.setAttribute("y2", b.y);
      line.setAttribute("class", "graph-edge");
      edgeGroup.appendChild(line);
    }
    graphSvg.appendChild(edgeGroup);

    const nodeGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");
    for (const n of nodes) {
      const p = pos.get(n.id);
      const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
      g.setAttribute("class", "graph-node");
      g.setAttribute("transform", `translate(${p.x},${p.y})`);

      const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      circle.setAttribute("r", NODE_RADIUS[n.type] || 9);
      circle.setAttribute("fill", NODE_COLORS[n.type] || "#93a0b3");
      g.appendChild(circle);

      const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
      label.setAttribute("y", (NODE_RADIUS[n.type] || 9) + 13);
      label.setAttribute("text-anchor", "middle");
      label.setAttribute("class", "graph-label");
      label.textContent = n.label;
      g.appendChild(label);

      if (n.type === "cve") {
        g.style.cursor = "pointer";
        g.addEventListener("click", () => {
          askAI(`What is ${n.label.split(" ")[0]} and how serious is it?`);
        });
      }

      nodeGroup.appendChild(g);
    }
    graphSvg.appendChild(nodeGroup);
  }

  async function buildGraph() {
    const domain = graphDomainInput.value.trim();
    if (!domain) {
      graphStatus.textContent = "Enter a domain first.";
      return;
    }
    const keys = loadKeys();
    graphStatus.textContent = "Building…";
    graphSvg.innerHTML = "";
    try {
      const resp = await fetch("/api/graph", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, shodan_key: keys.shodan || "" }),
      });
      const data = await resp.json();
      if (!data.ok) {
        graphStatus.textContent = data.error || "Failed to build graph.";
        return;
      }
      renderGraph(data.nodes, data.edges);
      const parts = [`${data.nodes.length} nodes`, `${data.edges.length} edges`];
      if (data.note) parts.push(data.note);
      graphStatus.textContent = parts.join(" — ");
    } catch (err) {
      graphStatus.textContent = `Request failed: ${err}`;
    }
  }

  document.getElementById("graph-build").addEventListener("click", buildGraph);
  graphDomainInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") buildGraph();
  });

  render();
})();
