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

  render();
})();
