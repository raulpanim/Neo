(() => {
  "use strict";

  const COLS = 7;
  const ROWS = 7;
  const ATTACK_PER_GEM = 6;
  const HEAL_PER_GEM = 5;
  const SWIPE_THRESHOLD = 18;

  const GEM_TYPES = ["fire", "water", "earth", "bolt", "dark"];
  const ALL_GEMS = [...GEM_TYPES, "heal"];
  const GEM_EMOJI = {
    fire: "\u{1F525}",
    water: "\u{1F4A7}",
    earth: "\u{1F33F}",
    bolt: "⚡",
    dark: "\u{1F52E}",
    heal: "❤️",
  };

  const ENEMIES = [
    { name: "Slime", emoji: "\u{1F7E2}" },
    { name: "Goblin", emoji: "\u{1F47A}" },
    { name: "Wolf", emoji: "\u{1F43A}" },
    { name: "Skeleton", emoji: "\u{1F480}" },
    { name: "Golem", emoji: "\u{1FAA8}" },
    { name: "Wraith", emoji: "\u{1F47B}" },
    { name: "Dragon", emoji: "\u{1F409}" },
  ];

  const boardEl = document.getElementById("board");
  const floatersEl = document.getElementById("floaters");
  const messageEl = document.getElementById("message");
  const levelEl = document.getElementById("level");
  const playerHpEl = document.getElementById("player-hp");
  const playerMaxHpEl = document.getElementById("player-max-hp");
  const playerBarEl = document.getElementById("player-bar");
  const enemyNameEl = document.getElementById("enemy-name");
  const enemyHpEl = document.getElementById("enemy-hp");
  const enemyMaxHpEl = document.getElementById("enemy-max-hp");
  const enemyBarEl = document.getElementById("enemy-bar");
  const restartBtn = document.getElementById("restart-btn");
  const overlayEl = document.getElementById("overlay");
  const overlayTitleEl = document.getElementById("overlay-title");
  const overlayTextEl = document.getElementById("overlay-text");
  const overlayBtn = document.getElementById("overlay-btn");

  boardEl.style.setProperty("--cols", COLS);

  let board = [];
  let state = null;
  let busy = false;
  let selected = null;
  let dragStart = null;

  const idx = (r, c) => r * COLS + c;
  const sleep = (ms) => new Promise((res) => setTimeout(res, ms));
  const randomGemId = () => ALL_GEMS[Math.floor(Math.random() * ALL_GEMS.length)];

  function newEnemyForLevel(level) {
    const def = ENEMIES[(level - 1) % ENEMIES.length];
    const scale = 1 + Math.floor((level - 1) / ENEMIES.length) * 0.5;
    const maxHp = Math.round((40 + level * 22) * scale);
    const atk = Math.round((6 + level * 2.2) * scale);
    return { name: def.name, emoji: def.emoji, maxHp, hp: maxHp, atk };
  }

  function pickSafeGem(r, c) {
    for (let tries = 0; tries < 50; tries++) {
      const g = randomGemId();
      const left2 = c >= 2 && board[idx(r, c - 1)] === g && board[idx(r, c - 2)] === g;
      const up2 = r >= 2 && board[idx(r - 1, c)] === g && board[idx(r - 2, c)] === g;
      if (!left2 && !up2) return g;
    }
    return randomGemId();
  }

  function generateBoard() {
    board = new Array(ROWS * COLS).fill(null);
    for (let r = 0; r < ROWS; r++) {
      for (let c = 0; c < COLS; c++) {
        board[idx(r, c)] = pickSafeGem(r, c);
      }
    }
  }

  function buildBoardDom() {
    boardEl.innerHTML = "";
    for (let r = 0; r < ROWS; r++) {
      for (let c = 0; c < COLS; c++) {
        const cell = document.createElement("div");
        cell.className = "cell";
        cell.dataset.r = r;
        cell.dataset.c = c;
        boardEl.appendChild(cell);
      }
    }
  }

  const cellEl = (r, c) => boardEl.children[idx(r, c)];

  function renderCell(r, c) {
    const el = cellEl(r, c);
    el.className = "cell";
    el.textContent = GEM_EMOJI[board[idx(r, c)]] || "";
  }

  function renderAllCells() {
    for (let r = 0; r < ROWS; r++) {
      for (let c = 0; c < COLS; c++) renderCell(r, c);
    }
  }

  function updateHud() {
    levelEl.textContent = state.level;
    playerHpEl.textContent = state.playerHp;
    playerMaxHpEl.textContent = state.playerMaxHp;
    playerBarEl.style.width = `${Math.max(0, (state.playerHp / state.playerMaxHp) * 100)}%`;
    enemyNameEl.textContent = `${state.enemy.emoji} ${state.enemy.name}`;
    enemyHpEl.textContent = Math.max(0, state.enemy.hp);
    enemyMaxHpEl.textContent = state.enemy.maxHp;
    enemyBarEl.style.width = `${Math.max(0, (state.enemy.hp / state.enemy.maxHp) * 100)}%`;
  }

  function setMessage(text) {
    messageEl.textContent = text;
  }

  function spawnFloater(target, text, cls) {
    const el = document.createElement("div");
    el.className = `floater ${cls}`;
    el.textContent = text;
    el.style.left = `${20 + Math.random() * 60}%`;
    el.style.top = target === "enemy" ? "8%" : "82%";
    floatersEl.appendChild(el);
    setTimeout(() => el.remove(), 900);
  }

  function findMatches() {
    const matched = new Set();
    for (let r = 0; r < ROWS; r++) {
      let runStart = 0;
      for (let c = 1; c <= COLS; c++) {
        const cur = c < COLS ? board[idx(r, c)] : null;
        const prev = board[idx(r, c - 1)];
        if (cur !== prev) {
          if (c - runStart >= 3) {
            for (let k = runStart; k < c; k++) matched.add(idx(r, k));
          }
          runStart = c;
        }
      }
    }
    for (let c = 0; c < COLS; c++) {
      let runStart = 0;
      for (let r = 1; r <= ROWS; r++) {
        const cur = r < ROWS ? board[idx(r, c)] : null;
        const prev = board[idx(r - 1, c)];
        if (cur !== prev) {
          if (r - runStart >= 3) {
            for (let k = runStart; k < r; k++) matched.add(idx(k, c));
          }
          runStart = r;
        }
      }
    }
    return matched;
  }

  function collapseAndRefill(matchedSet) {
    const newCells = [];
    for (let c = 0; c < COLS; c++) {
      let writeRow = ROWS - 1;
      for (let r = ROWS - 1; r >= 0; r--) {
        if (!matchedSet.has(idx(r, c))) {
          board[idx(writeRow, c)] = board[idx(r, c)];
          writeRow--;
        }
      }
      for (let r = writeRow; r >= 0; r--) {
        board[idx(r, c)] = randomGemId();
        newCells.push(idx(r, c));
      }
    }
    return newCells;
  }

  function swapBoard(a, b) {
    const ia = idx(a.r, a.c);
    const ib = idx(b.r, b.c);
    [board[ia], board[ib]] = [board[ib], board[ia]];
  }

  function isNeighbor(a, b) {
    return (
      (Math.abs(a.r - b.r) === 1 && a.c === b.c) ||
      (Math.abs(a.c - b.c) === 1 && a.r === b.r)
    );
  }

  function setSelected(cell) {
    if (selected) cellEl(selected.r, selected.c).classList.remove("selected");
    selected = cell;
    if (selected) cellEl(selected.r, selected.c).classList.add("selected");
  }

  function flashInvalid(a, b) {
    [a, b].forEach(({ r, c }) => {
      const el = cellEl(r, c);
      el.classList.add("shake");
      setTimeout(() => el.classList.remove("shake"), 300);
    });
  }

  async function resolveCascades() {
    let combo = 1;
    while (true) {
      const matched = findMatches();
      if (matched.size === 0) break;

      const counts = {};
      matched.forEach((i) => {
        const g = board[i];
        counts[g] = (counts[g] || 0) + 1;
      });
      matched.forEach((i) => cellEl(Math.floor(i / COLS), i % COLS).classList.add("matched"));
      await sleep(200);

      let dmg = 0;
      let heal = 0;
      for (const [g, count] of Object.entries(counts)) {
        if (g === "heal") heal += Math.round(count * HEAL_PER_GEM * combo);
        else dmg += Math.round(count * ATTACK_PER_GEM * combo);
      }
      if (dmg > 0) {
        state.enemy.hp = Math.max(0, state.enemy.hp - dmg);
        spawnFloater("enemy", `-${dmg}`, "dmg");
      }
      if (heal > 0) {
        state.playerHp = Math.min(state.playerMaxHp, state.playerHp + heal);
        spawnFloater("player", `+${heal}`, "heal");
      }
      if (dmg > 0 || heal > 0) updateHud();

      const newCells = collapseAndRefill(matched);
      renderAllCells();
      newCells.forEach((i) => cellEl(Math.floor(i / COLS), i % COLS).classList.add("dropping"));
      await sleep(220);

      combo += 0.5;
      if (state.enemy.hp <= 0) break;
    }
  }

  function enemyTurn() {
    const variance = Math.round(state.enemy.atk * 0.25);
    const dmg = Math.max(1, state.enemy.atk + Math.floor(Math.random() * (variance * 2 + 1)) - variance);
    state.playerHp = Math.max(0, state.playerHp - dmg);
    spawnFloater("player", `-${dmg}`, "dmg");
    updateHud();
    setMessage(`${state.enemy.name} hits you for ${dmg}!`);
    if (state.playerHp <= 0) handleDefeat();
  }

  function showOverlay(title, text, btnLabel) {
    overlayTitleEl.textContent = title;
    overlayTextEl.textContent = text;
    overlayBtn.textContent = btnLabel;
    overlayEl.classList.remove("hidden");
  }

  function hideOverlay() {
    overlayEl.classList.add("hidden");
  }

  function handleVictory() {
    const rewardHeal = Math.round(state.playerMaxHp * 0.3);
    state.level += 1;
    state.playerMaxHp += 8;
    state.playerHp = Math.min(state.playerMaxHp, state.playerHp + rewardHeal);
    state.enemy = newEnemyForLevel(state.level);
    updateHud();
    generateBoard();
    renderAllCells();
    setMessage("Victory! A new challenger appears.");
    showOverlay(
      "Victory!",
      `You defeated the enemy and healed ${rewardHeal} HP. Now facing a level ${state.level} ${state.enemy.name} ${state.enemy.emoji}.`,
      "Continue"
    );
    overlayBtn.dataset.mode = "continue";
  }

  function handleDefeat() {
    setMessage("You were defeated...");
    showOverlay("Defeated...", `You reached level ${state.level}. Tap restart to try again.`, "Restart");
    overlayBtn.dataset.mode = "restart";
    busy = true;
  }

  async function attemptSwap(a, b) {
    if (busy) return;
    busy = true;
    swapBoard(a, b);
    renderCell(a.r, a.c);
    renderCell(b.r, b.c);

    const matched = findMatches();
    if (matched.size === 0) {
      await sleep(140);
      swapBoard(a, b);
      renderCell(a.r, a.c);
      renderCell(b.r, b.c);
      flashInvalid(a, b);
      busy = false;
      return;
    }

    setMessage("Nice match!");
    await resolveCascades();
    updateHud();

    if (state.enemy.hp <= 0) {
      await sleep(200);
      handleVictory();
      return;
    }

    await sleep(250);
    enemyTurn();
    busy = false;
  }

  function newGame() {
    state = {
      level: 1,
      playerMaxHp: 100,
      playerHp: 100,
      enemy: newEnemyForLevel(1),
    };
    selected = null;
    dragStart = null;
    busy = false;
    generateBoard();
    renderAllCells();
    updateHud();
    setMessage("Match gems to attack the enemy!");
    hideOverlay();
  }

  boardEl.addEventListener("pointerdown", (e) => {
    if (busy) return;
    const cellDiv = e.target.closest(".cell");
    if (!cellDiv) return;
    const cell = { r: +cellDiv.dataset.r, c: +cellDiv.dataset.c };

    if (selected && !(selected.r === cell.r && selected.c === cell.c)) {
      if (isNeighbor(selected, cell)) {
        const a = selected;
        setSelected(null);
        attemptSwap(a, cell);
        return;
      }
    }

    setSelected(cell);
    dragStart = { r: cell.r, c: cell.c, x: e.clientX, y: e.clientY, pointerId: e.pointerId, moved: false };
  });

  document.addEventListener("pointermove", (e) => {
    if (!dragStart || busy || e.pointerId !== dragStart.pointerId) return;
    const dx = e.clientX - dragStart.x;
    const dy = e.clientY - dragStart.y;
    if (Math.hypot(dx, dy) < SWIPE_THRESHOLD) return;

    let dr = 0;
    let dc = 0;
    if (Math.abs(dx) > Math.abs(dy)) dc = dx > 0 ? 1 : -1;
    else dr = dy > 0 ? 1 : -1;

    const start = { r: dragStart.r, c: dragStart.c };
    const target = { r: start.r + dr, c: start.c + dc };
    dragStart = null;
    setSelected(null);

    if (target.r >= 0 && target.r < ROWS && target.c >= 0 && target.c < COLS) {
      attemptSwap(start, target);
    }
  });

  document.addEventListener("pointerup", () => {
    dragStart = null;
  });

  restartBtn.addEventListener("click", () => newGame());

  overlayBtn.addEventListener("click", () => {
    if (overlayBtn.dataset.mode === "restart") {
      newGame();
    } else {
      hideOverlay();
      busy = false;
    }
  });

  buildBoardDom();
  newGame();
})();
