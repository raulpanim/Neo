(() => {
  const targetInput = document.getElementById("graph-target");
  const buildBtn = document.getElementById("graph-btn");
  const status = document.getElementById("graph-status");
  const canvas = document.getElementById("graph-canvas");
  const ctx = canvas.getContext("2d");

  const COLORS = {
    domain: "#5eb0ff",
    subdomain: "#38c977",
    ip: "#f0a340",
  };

  let nodes = [];
  let edges = [];
  let simTimer = null;
  let dragNode = null;
  let hoverNode = null;

  function resetSim(newNodes, newEdges) {
    const w = canvas.width;
    const h = canvas.height;
    nodes = newNodes.map((n, i) => ({
      ...n,
      x: w / 2 + Math.cos(i) * 50 + Math.random() * 20,
      y: h / 2 + Math.sin(i) * 50 + Math.random() * 20,
      vx: 0,
      vy: 0,
    }));
    const byId = new Map(nodes.map((n) => [n.id, n]));
    edges = newEdges
      .map((e) => ({ source: byId.get(e.source), target: byId.get(e.target) }))
      .filter((e) => e.source && e.target);
  }

  function step() {
    const w = canvas.width;
    const h = canvas.height;
    const centerX = w / 2;
    const centerY = h / 2;

    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j];
        let dx = a.x - b.x;
        let dy = a.y - b.y;
        let distSq = dx * dx + dy * dy || 0.01;
        const repel = 2200 / distSq;
        const dist = Math.sqrt(distSq);
        dx /= dist;
        dy /= dist;
        a.vx += dx * repel;
        a.vy += dy * repel;
        b.vx -= dx * repel;
        b.vy -= dy * repel;
      }
      a.vx += (centerX - a.x) * 0.002;
      a.vy += (centerY - a.y) * 0.002;
    }

    for (const e of edges) {
      const dx = e.target.x - e.source.x;
      const dy = e.target.y - e.source.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
      const targetLen = 90;
      const force = (dist - targetLen) * 0.02;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      e.source.vx += fx;
      e.source.vy += fy;
      e.target.vx -= fx;
      e.target.vy -= fy;
    }

    for (const n of nodes) {
      if (n === dragNode) {
        n.vx = 0;
        n.vy = 0;
        continue;
      }
      n.vx *= 0.85;
      n.vy *= 0.85;
      n.x += n.vx;
      n.y += n.vy;
      n.x = Math.max(20, Math.min(w - 20, n.x));
      n.y = Math.max(20, Math.min(h - 20, n.y));
    }
  }

  function draw() {
    const w = canvas.width;
    const h = canvas.height;
    const styles = getComputedStyle(document.documentElement);
    ctx.clearRect(0, 0, w, h);
    ctx.strokeStyle = styles.getPropertyValue("--border").trim() || "#2a303a";
    ctx.lineWidth = 1;
    for (const e of edges) {
      ctx.beginPath();
      ctx.moveTo(e.source.x, e.source.y);
      ctx.lineTo(e.target.x, e.target.y);
      ctx.stroke();
    }
    for (const n of nodes) {
      const r = n.type === "domain" ? 9 : n.type === "ip" ? 6 : 7;
      ctx.beginPath();
      ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
      ctx.fillStyle = COLORS[n.type] || "#93a0b3";
      ctx.fill();
      if (n === hoverNode) {
        ctx.lineWidth = 2;
        ctx.strokeStyle = styles.getPropertyValue("--text").trim() || "#e6e9ee";
        ctx.stroke();
      }
      ctx.fillStyle = styles.getPropertyValue("--text").trim() || "#e6e9ee";
      ctx.font = "11px -apple-system, BlinkMacSystemFont, sans-serif";
      ctx.fillText(n.label, n.x + r + 4, n.y + 4);
    }
  }

  function loop() {
    step();
    draw();
    simTimer = requestAnimationFrame(loop);
  }

  function nodeAt(x, y) {
    for (let i = nodes.length - 1; i >= 0; i--) {
      const n = nodes[i];
      const dx = n.x - x;
      const dy = n.y - y;
      if (dx * dx + dy * dy <= 144) return n;
    }
    return null;
  }

  function canvasPos(evt) {
    const rect = canvas.getBoundingClientRect();
    return {
      x: ((evt.clientX - rect.left) / rect.width) * canvas.width,
      y: ((evt.clientY - rect.top) / rect.height) * canvas.height,
    };
  }

  canvas.addEventListener("mousedown", (evt) => {
    const pos = canvasPos(evt);
    dragNode = nodeAt(pos.x, pos.y);
  });
  canvas.addEventListener("mousemove", (evt) => {
    const pos = canvasPos(evt);
    if (dragNode) {
      dragNode.x = pos.x;
      dragNode.y = pos.y;
      canvas.style.cursor = "grabbing";
    } else {
      hoverNode = nodeAt(pos.x, pos.y);
      canvas.style.cursor = hoverNode ? "pointer" : "default";
      canvas.title = hoverNode ? hoverNode.label : "";
    }
  });
  window.addEventListener("mouseup", () => {
    dragNode = null;
  });

  async function buildGraph() {
    const target = targetInput.value.trim().toLowerCase();
    if (!target) {
      status.textContent = "Enter a domain first.";
      return;
    }
    status.textContent = "Building graph…";
    buildBtn.disabled = true;
    try {
      const resp = await fetch("/api/graph", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
      });
      const result = await resp.json();
      if (!result.ok) {
        status.textContent = result.error || "No graph data.";
        if (simTimer) cancelAnimationFrame(simTimer);
        nodes = [];
        edges = [];
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        return;
      }
      status.textContent = `${result.nodes.length} nodes, ${result.edges.length} edges.`;
      resetSim(result.nodes, result.edges);
      if (simTimer) cancelAnimationFrame(simTimer);
      loop();
    } catch (err) {
      status.textContent = `Request failed: ${err}`;
    } finally {
      buildBtn.disabled = false;
    }
  }

  buildBtn.addEventListener("click", buildGraph);
  targetInput.addEventListener("keydown", (evt) => {
    if (evt.key === "Enter") buildGraph();
  });
})();
