// blacksite://term background and cursor. Decoration only: aria-hidden, never needed to use
// the console, and the rain stays off under prefers-reduced-motion or `fx off`.
//
//   Rain    three depth layers, each column its own speed and trail length. The far field is
//           drawn at half resolution and softened, the foreground is large and out of focus, the
//           middle is sharp. Katakana are mirrored and trails shimmer. It shows behind sign-in and
//           as the console's screensaver; while you work it is paused, not just hidden.
//   Cursor  a blinking block for single-line fields, since browsers draw a thin caret.
"use strict";
window.FX = (() => {
  const calm = matchMedia("(prefers-reduced-motion: reduce)");
  let wanted = true;
  try { wanted = localStorage.getItem("blacksite.term.fx") !== "off"; } catch { /* storage unavailable */ }
  const motion = () => wanted && !calm.matches;

  const KATA = "ｦｧｨｩｪｫｬｭｮｯｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ";
  const REST = "0123456789Z:.=*+<>¦|";
  const pick = () => (Math.random() < 0.74 ? KATA[(Math.random() * KATA.length) | 0] : REST[(Math.random() * REST.length) | 0]);
  const rand = (a, b) => a + Math.random() * (b - a);
  const MONO = '"MesloLGS NF", "MesloLGS Nerd Font", "MesloLGM Nerd Font", ui-monospace, "SF Mono", Menlo, monospace';
  // Read from term.css (--rain, --rain-hot, --rain-head, --rain-far) so the cursor matches.
  const COLORS = { head: "#ecfff2", hot: "#96ffb4", trail: "#22e05a", far: "#16963e" };
  function readColors() {
    const cs = getComputedStyle(document.documentElement);
    for (const [key, name] of [["head", "--rain-head"], ["hot", "--rain-hot"], ["trail", "--rain"], ["far", "--rain-far"]]) {
      COLORS[key] = cs.getPropertyValue(name).trim() || COLORS[key];
    }
  }

  // size px, speed rows/s, trail length in cells, respawn pause in s, shimmer per cell per s.
  const LAYERS = [
    { key: "far", size: 11, speed: [4, 11], len: [8, 24], pause: [0, 2.5], alpha: 0.5, shimmer: 1.2, res: 0.5, blur: 0.8 },
    { key: "mid", size: 16, speed: [7, 21], len: [8, 32], pause: [0.2, 4], alpha: 0.95, shimmer: 2.2, res: 1, blur: 0 },
    { key: "near", size: 28, speed: [18, 34], len: [5, 14], pause: [3, 14], alpha: 0.7, shimmer: 3, res: 1, blur: 2.4 },
  ];

  const canvas = () => document.getElementById("rain");
  let ctx = null, W = 0, H = 0, ratio = 1, layers = [], raf = 0, last = 0, frame = 0, pace = 1, target = 1, shown = true;

  function respawn(layer, s, initial = false) {
    s.speed = rand(...layer.speed);
    s.len = Math.round(rand(...layer.len));
    s.cells = []; s.flip = [];
    s.wait = initial ? rand(0, layer.pause[1] * 0.6) : rand(...layer.pause);
    // The first frame is already raining: initial streams start anywhere on screen.
    s.y = initial ? rand(-s.len, H / layer.size) : -1;
    const lit = Math.max(0, Math.min(s.len, Math.floor(s.y) + 1));
    for (let k = 0; k < lit; k++) { s.cells.push(pick()); s.flip.push(Math.random() < 0.8); }
  }

  function resize() {
    const c = canvas();
    ratio = Math.min(window.devicePixelRatio || 1, 2);
    W = innerWidth; H = innerHeight;
    c.width = Math.ceil(W * ratio); c.height = Math.ceil(H * ratio);
    layers = LAYERS.map((spec) => {
      const streams = [];
      for (let i = 0; i < Math.ceil(W / spec.size) + 1; i++) {
        if (spec.key === "near" && Math.random() > 0.35) continue;  // the foreground is sparse
        const s = { x: i * spec.size };
        respawn(spec, s, true);
        streams.push(s);
      }
      let off = null;
      if (spec.res !== 1 || spec.blur) {
        off = document.createElement("canvas");
        off.width = Math.ceil(W * ratio * spec.res); off.height = Math.ceil(H * ratio * spec.res);
      }
      return { spec, streams, off, octx: off && off.getContext("2d") };
    });
  }

  function step(layer, dt) {
    const { spec } = layer;
    for (const s of layer.streams) {
      if (s.wait > 0) { s.wait -= dt; continue; }
      const before = Math.floor(s.y);
      s.y += s.speed * pace * dt;
      for (let r = before; r < Math.floor(s.y); r++) {
        s.cells.unshift(pick()); s.flip.unshift(Math.random() < 0.8);
        if (s.cells.length > s.len) { s.cells.pop(); s.flip.pop(); }
      }
      if (s.cells.length && Math.random() < 0.6) s.cells[0] = pick();  // the head flickers
      const chance = spec.shimmer * dt * 0.15;
      for (let k = 1; k < s.cells.length; k++) if (Math.random() < chance) s.cells[k] = pick();
      if ((Math.floor(s.y) - s.len) * spec.size > H) respawn(spec, s);
    }
  }

  function draw(target, layer, scale) {
    const { spec } = layer;
    const size = spec.size;
    target.font = `${size}px ${MONO}`;
    target.textBaseline = "top";
    let fill = "";
    for (const s of layer.streams) {
      if (s.wait > 0 || !s.cells.length) continue;
      const head = Math.floor(s.y);
      for (let k = 0; k < s.cells.length; k++) {
        const py = (head - k) * size;
        if (py < -size || py > H) continue;
        const fade = 1 - k / s.len;
        const alpha = spec.alpha * fade * fade;
        if (alpha < 0.03) continue;
        const color = k === 0 ? COLORS.head : k < 3 ? COLORS.hot : spec.key === "far" ? COLORS.far : COLORS.trail;
        if (color !== fill) { target.fillStyle = color; fill = color; }
        target.globalAlpha = alpha;
        if (s.flip[k]) target.setTransform(-scale, 0, 0, scale, (s.x + size) * scale, py * scale);
        else target.setTransform(scale, 0, 0, scale, s.x * scale, py * scale);
        target.fillText(s.cells[k], 0, 0);
      }
      if (spec.key !== "far" && head * size < H) {
        target.shadowColor = COLORS.hot; target.shadowBlur = spec.key === "near" ? 18 : 10;
        target.globalAlpha = spec.alpha; target.fillStyle = COLORS.head; fill = COLORS.head;
        target.setTransform(scale, 0, 0, scale, s.x * scale, head * size * scale);
        target.fillText(s.cells[0], 0, 0);
        target.shadowBlur = 0;
      }
    }
    target.setTransform(1, 0, 0, 1, 0, 0);
    target.globalAlpha = 1;
  }

  function tick(now) {
    raf = requestAnimationFrame(tick);
    if (now - last < 15) return;
    const dt = Math.min(0.05, (now - last) / 1000 || 0.016);
    last = now; frame++;
    pace += (target - pace) * Math.min(1, dt * 1.5);  // ease between idle and busy
    const c = canvas();
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, c.width, c.height);
    for (const layer of layers) {
      step(layer, dt);
      const { spec } = layer;
      if (!layer.off) { draw(ctx, layer, ratio); continue; }
      // The far field redraws every other frame; it is soft enough that nobody can tell.
      if (spec.key !== "far" || frame % 2 === 0) {
        layer.octx.setTransform(1, 0, 0, 1, 0, 0);
        layer.octx.clearRect(0, 0, layer.off.width, layer.off.height);
        draw(layer.octx, layer, ratio * spec.res);
      }
      if (spec.blur) ctx.filter = `blur(${spec.blur * ratio}px)`;
      ctx.drawImage(layer.off, 0, 0, c.width, c.height);
      ctx.filter = "none";
    }
  }

  function start() {
    const c = canvas();
    if (!c) return;
    c.hidden = !motion();
    if (!motion() || document.hidden || !shown) { stop(); return; }
    if (!ctx) {
      readColors();
      ctx = c.getContext("2d");
      addEventListener("resize", () => { if (ctx) resize(); });
      resize();
    }
    if (!raf) { last = performance.now(); raf = requestAnimationFrame(tick); }
  }

  function stop() { cancelAnimationFrame(raf); raf = 0; }

  // Block cursor -------------------------------------------------------------------------
  const block = document.createElement("div");
  block.className = "fx-cursor";
  block.setAttribute("aria-hidden", "true");
  block.hidden = true;
  const ruler = document.createElement("canvas").getContext("2d");
  let typingTimer = 0;
  const SINGLE = /^(text|password|search|email|url|tel|)$/;
  const eligible = (node) => node && node.tagName === "INPUT" && SINGLE.test(node.type) && !node.readOnly && !node.disabled;

  // Follows the focused field every frame; idles on a slow poll when no field has focus, so
  // programmatic focus and window switches never leave it behind.
  function watch() {
    const input = document.activeElement;
    if (eligible(input)) { place(input); requestAnimationFrame(watch); }
    else { block.hidden = true; setTimeout(watch, 200); }
  }

  function place(input) {
    const cs = getComputedStyle(input);
    ruler.font = `${cs.fontStyle} ${cs.fontWeight} ${cs.fontSize} ${cs.fontFamily}`;
    let at = input.value.length;
    try { if (input.selectionEnd !== null) at = input.selectionDirection === "backward" ? input.selectionStart : input.selectionEnd; } catch { /* no selection API */ }
    const before = input.type === "password" ? "•".repeat(at) : input.value.slice(0, at);
    const spacing = parseFloat(cs.letterSpacing) || 0;
    const cell = ruler.measureText("M").width + spacing;
    const rect = input.getBoundingClientRect();
    const inner = rect.left + parseFloat(cs.borderLeftWidth) + parseFloat(cs.paddingLeft);
    const x = Math.min(inner + ruler.measureText(before).width + spacing * at - input.scrollLeft, rect.right - parseFloat(cs.paddingRight) - cell);
    const h = Math.round(parseFloat(cs.fontSize) * 1.28);
    block.style.cssText = `left:${x}px;top:${rect.top + (rect.height - h) / 2}px;width:${cell}px;height:${h}px`;
    block.hidden = rect.width === 0;
  }

  function typed() {
    block.classList.add("typing");
    clearTimeout(typingTimer);
    typingTimer = setTimeout(() => block.classList.remove("typing"), 520);
  }

  function initCursor() {
    document.body.append(block);
    document.documentElement.classList.add("fx-caret");
    document.addEventListener("keydown", (event) => { if (eligible(event.target)) typed(); });
    document.addEventListener("input", (event) => { if (eligible(event.target)) typed(); });
    watch();
  }

  function setWanted(on) {
    wanted = on;
    try { localStorage.setItem("blacksite.term.fx", on ? "on" : "off"); } catch { /* storage unavailable */ }
    start();
  }

  document.addEventListener("visibilitychange", () => (document.hidden ? stop() : start()));
  calm.addEventListener("change", start);

  return {
    start, initCursor, setWanted,
    get on() { return motion(); },
    show(on) { shown = on; start(); },
    recolor() { readColors(); },
    busy(on) { target = on ? 1.35 : 1; },
  };
})();
