(() => {
  "use strict";

  const BOARD_COLS = 7;
  const BOARD_ROWS = 7;
  const ATTACK_PER_GEM = 6;
  const HEAL_PER_GEM = 5;
  const SWIPE_THRESHOLD = 18;

  const MAP_COLS = 9;
  const MAP_ROWS = 7;

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

  const PLAYER_EMOJI = "\u{1F9D9}";

  const boardEl = document.getElementById("board");
  const floatersEl = document.getElementById("floaters");
  const messageEl = document.getElementById("message");
  const levelEl = document.getElementById("level");
  const playerHpEl = document.getElementById("player-hp");
  const playerMaxHpEl = document.getElementById("player-max-hp");
  const playerBarEl = document.getElementById("player-bar");
  const enemyRowEl = document.getElementById("enemy-row");
  const enemyNameEl = document.getElementById("enemy-name");
  const enemyHpEl = document.getElementById("enemy-hp");
  const enemyMaxHpEl = document.getElementById("enemy-max-hp");
  const enemyBarEl = document.getElementById("enemy-bar");
  const restartBtn = document.getElementById("restart-btn");
  const overlayEl = document.getElementById("overlay");
  const overlayTitleEl = document.getElementById("overlay-title");
  const overlayTextEl = document.getElementById("overlay-text");
  const overlayBtn = document.getElementById("overlay-btn");
  const overworldEl = document.getElementById("overworld");
  const battleEl = document.getElementById("battle");
  const mapEl = document.getElementById("map");
  const dpadEl = document.querySelector(".dpad");

  boardEl.style.setProperty("--cols", BOARD_COLS);
  mapEl.style.setProperty("--map-cols", MAP_COLS);

  // --- battle board state ---
  let board = [];
  let busy = false;
  let selected = null;
  let dragStart = null;

  // --- overworld state ---
  let tiles = [];
  let player = { r: 1, c: 1 };
  let mapEnemies = [];

  // --- persistent run state ---
  let state = null;
  let battleActive = false;
  let activeMapEnemy = null;
  let currentEnemy = null;

  const idxBoard = (r, c) => r * BOARD_COLS + c;
  const idxMap = (r, c) => r * MAP_COLS + c;
  const sleep = (ms) => new Promise((res) => setTimeout(res, ms));
  const randomGemId = () => ALL_GEMS[Math.floor(Math.random() * ALL_GEMS.length)];

  // ---------------------------------------------------------------------
  // Overworld map
  // ---------------------------------------------------------------------

  function makeEnemyStats(level) {
    const def = ENEMIES[Math.floor(Math.random() * ENEMIES.length)];
    const maxHp = Math.round(40 + level * 20 + Math.random() * 12);
    const atk = Math.round(6 + level * 2 + Math.random() * 3);
    return { name: def.name, emoji: def.emoji, maxHp, atk };
  }

  function generateMap() {
    tiles = new Array(MAP_ROWS * MAP_COLS).fill("grass");
    for (let c = 0; c < MAP_COLS; c++) {
      tiles[idxMap(0, c)] = "tree";
      tiles[idxMap(MAP_ROWS - 1, c)] = "tree";
    }
    for (let r = 0; r < MAP_ROWS; r++) {
      tiles[idxMap(r, 0)] = "water";
      tiles[idxMap(r, MAP_COLS - 1)] = "water";
    }

    player = { r: 1, c: 1 };

    const enemyCount = Math.min(4 + Math.floor((state.level - 1) / 1), 9);
    mapEnemies = [];
    let guard = 0;
    while (mapEnemies.length < enemyCount && guard < 500) {
      guard++;
      const r = 1 + Math.floor(Math.random() * (MAP_ROWS - 2));
      const c = 1 + Math.floor(Math.random() * (MAP_COLS - 2));
      const tooCloseToPlayer = Math.abs(r - player.r) + Math.abs(c - player.c) < 3;
      const occupied = mapEnemies.some((e) => e.r === r && e.c === c);
      if (tooCloseToPlayer || occupied) continue;
      const stats = makeEnemyStats(state.level);
      mapEnemies.push({ r, c, alive: true, ...stats });
    }
  }

  function buildMapDom() {
    mapEl.innerHTML = "";
    for (let r = 0; r < MAP_ROWS; r++) {
      for (let c = 0; c < MAP_COLS; c++) {
        const t = document.createElement("div");
        t.className = "tile";
        t.dataset.r = r;
        t.dataset.c = c;
        mapEl.appendChild(t);
      }
    }
  }

  const tileEl = (r, c) => mapEl.children[idxMap(r, c)];

  function renderMap() {
    for (let r = 0; r < MAP_ROWS; r++) {
      for (let c = 0; c < MAP_COLS; c++) {
        const el = tileEl(r, c);
        const terrain = tiles[idxMap(r, c)];
        el.className = `tile ${terrain}`;
        el.textContent = terrain === "tree" ? "\u{1F332}" : terrain === "water" ? "\u{1F30A}" : "";

        const enemy = mapEnemies.find((e) => e.alive && e.r === r && e.c === c);
        if (enemy) {
          el.classList.add("has-enemy");
          el.textContent = enemy.emoji;
        }
        if (player.r === r && player.c === c) {
          el.classList.add("has-player");
          el.textContent = PLAYER_EMOJI;
        }
      }
    }
  }

  function attemptMove(dr, dc) {
    if (battleActive || !overlayEl.classList.contains("hidden")) return;
    const nr = player.r + dr;
    const nc = player.c + dc;
    if (nr < 0 || nr >= MAP_ROWS || nc < 0 || nc >= MAP_COLS) return;
    const terrain = tiles[idxMap(nr, nc)];
    if (terrain === "tree" || terrain === "water") return;

    const enemy = mapEnemies.find((e) => e.alive && e.r === nr && e.c === nc);
    if (enemy) {
      startBattle(enemy);
      return;
    }

    player.r = nr;
    player.c = nc;
    renderMap();
  }

  // ---------------------------------------------------------------------
  // Battle board
  // ---------------------------------------------------------------------

  function pickSafeGem(r, c) {
    for (let tries = 0; tries < 50; tries++) {
      const g = randomGemId();
      const left2 = c >= 2 && board[idxBoard(r, c - 1)] === g && board[idxBoard(r, c - 2)] === g;
      const up2 = r >= 2 && board[idxBoard(r - 1, c)] === g && board[idxBoard(r - 2, c)] === g;
      if (!left2 && !up2) return g;
    }
    return randomGemId();
  }

  function generateBoard() {
    board = new Array(BOARD_ROWS * BOARD_COLS).fill(null);
    for (let r = 0; r < BOARD_ROWS; r++) {
      for (let c = 0; c < BOARD_COLS; c++) {
        board[idxBoard(r, c)] = pickSafeGem(r, c);
      }
    }
  }

  function buildBoardDom() {
    boardEl.innerHTML = "";
    for (let r = 0; r < BOARD_ROWS; r++) {
      for (let c = 0; c < BOARD_COLS; c++) {
        const cell = document.createElement("div");
        cell.className = "cell";
        cell.dataset.r = r;
        cell.dataset.c = c;
        boardEl.appendChild(cell);
      }
    }
  }

  const cellEl = (r, c) => boardEl.children[idxBoard(r, c)];

  function renderCell(r, c) {
    const el = cellEl(r, c);
    el.className = "cell";
    el.textContent = GEM_EMOJI[board[idxBoard(r, c)]] || "";
  }

  function renderAllCells() {
    for (let r = 0; r < BOARD_ROWS; r++) {
      for (let c = 0; c < BOARD_COLS; c++) renderCell(r, c);
    }
  }

  function updateHud() {
    levelEl.textContent = state.level;
    playerHpEl.textContent = state.playerHp;
    playerMaxHpEl.textContent = state.playerMaxHp;
    playerBarEl.style.width = `${Math.max(0, (state.playerHp / state.playerMaxHp) * 100)}%`;
    if (currentEnemy) {
      enemyNameEl.textContent = `${currentEnemy.emoji} ${currentEnemy.name}`;
      enemyHpEl.textContent = Math.max(0, currentEnemy.hp);
      enemyMaxHpEl.textContent = currentEnemy.maxHp;
      enemyBarEl.style.width = `${Math.max(0, (currentEnemy.hp / currentEnemy.maxHp) * 100)}%`;
    }
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
    for (let r = 0; r < BOARD_ROWS; r++) {
      let runStart = 0;
      for (let c = 1; c <= BOARD_COLS; c++) {
        const cur = c < BOARD_COLS ? board[idxBoard(r, c)] : null;
        const prev = board[idxBoard(r, c - 1)];
        if (cur !== prev) {
          if (c - runStart >= 3) {
            for (let k = runStart; k < c; k++) matched.add(idxBoard(r, k));
          }
          runStart = c;
        }
      }
    }
    for (let c = 0; c < BOARD_COLS; c++) {
      let runStart = 0;
      for (let r = 1; r <= BOARD_ROWS; r++) {
        const cur = r < BOARD_ROWS ? board[idxBoard(r, c)] : null;
        const prev = board[idxBoard(r - 1, c)];
        if (cur !== prev) {
          if (r - runStart >= 3) {
            for (let k = runStart; k < r; k++) matched.add(idxBoard(k, c));
          }
          runStart = r;
        }
      }
    }
    return matched;
  }

  function collapseAndRefill(matchedSet) {
    const newCells = [];
    for (let c = 0; c < BOARD_COLS; c++) {
      let writeRow = BOARD_ROWS - 1;
      for (let r = BOARD_ROWS - 1; r >= 0; r--) {
        if (!matchedSet.has(idxBoard(r, c))) {
          board[idxBoard(writeRow, c)] = board[idxBoard(r, c)];
          writeRow--;
        }
      }
      for (let r = writeRow; r >= 0; r--) {
        board[idxBoard(r, c)] = randomGemId();
        newCells.push(idxBoard(r, c));
      }
    }
    return newCells;
  }

  function swapBoard(a, b) {
    const ia = idxBoard(a.r, a.c);
    const ib = idxBoard(b.r, b.c);
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
      matched.forEach((i) => cellEl(Math.floor(i / BOARD_COLS), i % BOARD_COLS).classList.add("matched"));
      await sleep(200);

      let dmg = 0;
      let heal = 0;
      for (const [g, count] of Object.entries(counts)) {
        if (g === "heal") heal += Math.round(count * HEAL_PER_GEM * combo);
        else dmg += Math.round(count * ATTACK_PER_GEM * combo);
      }
      if (dmg > 0) {
        currentEnemy.hp = Math.max(0, currentEnemy.hp - dmg);
        spawnFloater("enemy", `-${dmg}`, "dmg");
      }
      if (heal > 0) {
        state.playerHp = Math.min(state.playerMaxHp, state.playerHp + heal);
        spawnFloater("player", `+${heal}`, "heal");
      }
      if (dmg > 0 || heal > 0) updateHud();

      const newCells = collapseAndRefill(matched);
      renderAllCells();
      newCells.forEach((i) => cellEl(Math.floor(i / BOARD_COLS), i % BOARD_COLS).classList.add("dropping"));
      await sleep(220);

      combo += 0.5;
      if (currentEnemy.hp <= 0) break;
    }
  }

  function enemyTurn() {
    const variance = Math.round(currentEnemy.atk * 0.25);
    const dmg = Math.max(1, currentEnemy.atk + Math.floor(Math.random() * (variance * 2 + 1)) - variance);
    state.playerHp = Math.max(0, state.playerHp - dmg);
    spawnFloater("player", `-${dmg}`, "dmg");
    updateHud();
    setMessage(`${currentEnemy.name} hits you for ${dmg}!`);
    if (state.playerHp <= 0) handleDefeat();
  }

  function showOverlay(title, text, btnLabel, mode) {
    overlayTitleEl.textContent = title;
    overlayTextEl.textContent = text;
    overlayBtn.textContent = btnLabel;
    overlayBtn.dataset.mode = mode;
    overlayEl.classList.remove("hidden");
  }

  function hideOverlay() {
    overlayEl.classList.add("hidden");
  }

  function startBattle(mapEnemy) {
    battleActive = true;
    activeMapEnemy = mapEnemy;
    currentEnemy = { name: mapEnemy.name, emoji: mapEnemy.emoji, maxHp: mapEnemy.maxHp, atk: mapEnemy.atk, hp: mapEnemy.maxHp };

    overworldEl.classList.add("hidden");
    battleEl.classList.remove("hidden");
    enemyRowEl.classList.remove("hidden");

    selected = null;
    dragStart = null;
    busy = false;

    generateBoard();
    renderAllCells();
    updateHud();
    setMessage(`A wild ${currentEnemy.name} appears!`);
  }

  function exitBattleToMap() {
    battleActive = false;
    activeMapEnemy = null;
    currentEnemy = null;
    battleEl.classList.add("hidden");
    enemyRowEl.classList.add("hidden");
    overworldEl.classList.remove("hidden");

    if (mapEnemies.every((e) => !e.alive)) {
      generateMap();
      buildMapDom();
      setMessage("Area cleared! A tougher region appears.");
    } else {
      setMessage("Walk into an enemy to battle!");
    }
    renderMap();
  }

  function handleVictory() {
    activeMapEnemy.alive = false;
    const rewardHeal = Math.round(state.playerMaxHp * 0.25);
    state.level += 1;
    state.playerMaxHp += 8;
    state.playerHp = Math.min(state.playerMaxHp, state.playerHp + rewardHeal);
    updateHud();
    showOverlay(
      "Victory!",
      `You defeated the ${currentEnemy.name} and healed ${rewardHeal} HP. You're now level ${state.level}.`,
      "Continue",
      "continue"
    );
  }

  function handleDefeat() {
    setMessage("You were defeated...");
    showOverlay("Defeated...", `You reached level ${state.level}. Tap restart to try again.`, "Restart", "restart");
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

    if (currentEnemy.hp <= 0) {
      await sleep(200);
      handleVictory();
      return;
    }

    await sleep(250);
    enemyTurn();
    busy = false;
  }

  // ---------------------------------------------------------------------
  // Run lifecycle
  // ---------------------------------------------------------------------

  function newGame() {
    state = {
      level: 1,
      playerMaxHp: 100,
      playerHp: 100,
    };
    battleActive = false;
    activeMapEnemy = null;
    currentEnemy = null;
    busy = false;
    selected = null;
    dragStart = null;

    generateMap();
    buildMapDom();
    renderMap();
    updateHud();
    setMessage("Walk into an enemy to battle!");
    hideOverlay();

    battleEl.classList.add("hidden");
    enemyRowEl.classList.add("hidden");
    overworldEl.classList.remove("hidden");
  }

  // ---------------------------------------------------------------------
  // Input
  // ---------------------------------------------------------------------

  boardEl.addEventListener("pointerdown", (e) => {
    if (busy || !battleActive) return;
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

    if (target.r >= 0 && target.r < BOARD_ROWS && target.c >= 0 && target.c < BOARD_COLS) {
      attemptSwap(start, target);
    }
  });

  document.addEventListener("pointerup", () => {
    dragStart = null;
  });

  const DIRS = { up: [-1, 0], down: [1, 0], left: [0, -1], right: [0, 1] };
  const KEY_DIRS = {
    ArrowUp: "up", ArrowDown: "down", ArrowLeft: "left", ArrowRight: "right",
    w: "up", s: "down", a: "left", d: "right",
    W: "up", S: "down", A: "left", D: "right",
  };

  document.addEventListener("keydown", (e) => {
    const dir = KEY_DIRS[e.key];
    if (!dir) return;
    e.preventDefault();
    const [dr, dc] = DIRS[dir];
    attemptMove(dr, dc);
  });

  dpadEl.addEventListener("click", (e) => {
    const btn = e.target.closest(".dpad-btn");
    if (!btn) return;
    const [dr, dc] = DIRS[btn.dataset.dir];
    attemptMove(dr, dc);
  });

  restartBtn.addEventListener("click", () => newGame());

  overlayBtn.addEventListener("click", () => {
    if (overlayBtn.dataset.mode === "restart") {
      newGame();
    } else {
      hideOverlay();
      busy = false;
      exitBattleToMap();
    }
  });

  buildBoardDom();
  newGame();
})();
