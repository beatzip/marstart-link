import { useRef, useEffect } from "react";

// ╔══════════════════════════════════════════════════════════════════════╗
// ║  MARSTART LINK — LIVING MARS  ·  Premium Commercial Visualization   ║
// ║  Design: Linear / Arc / Tesla aesthetic with Mars brand identity    ║
// ╚══════════════════════════════════════════════════════════════════════╝

// ── Geometry ────────────────────────────────────────────────────────────
const W = 480, H = 448;    // canvas
const CX = 240, CY = 204;  // planet centre
const R  = 116;            // planet radius

// ── Brand Tokens ────────────────────────────────────────────────────────
const T = {
  space:    '#060810',   // background
  surface:  '#0E0E18',   // card surface
  border:   '#181828',   // card border
  txt1:     '#DCD8E8',   // primary text (warm white-purple)
  txt2:     '#4C4860',   // secondary
  txt3:     '#201E2C',   // very muted labels
  mars:     '#B83028',   // brand Mars red
  marsLt:   '#E05040',   // active Mars red
  cream:    '#F0DDD0',   // route lines (cream-white on dark red sphere)
  amber:    '#C08030',   // warning
  negative: '#C03028',   // critical (same as mars — cohesive)
  muted:    '#402A38',   // connected-but-muted
};

// ── Seeded deterministic star field (fewer = more elegant) ──────────────
let _s = 0xfeedface;
const _r = () => { _s = (_s * 1664525 + 1013904223) >>> 0; return _s / 0xffffffff; };
const STARS = Array.from({ length: 130 }, () => ({
  x: _r() * W, y: _r() * H,
  r: _r() < 0.07 ? 1.2 : _r() < 0.28 ? 0.72 : 0.38,
  a: 0.12 + _r() * 0.48,   // restrained opacity
  ph: _r() * 6.28,
}));

// ── Mars terrain features (normalised: centre=0, radius=1) ──────────────
const TERRAIN = [
  { cx:  0.24, cy: -0.26, rx: 0.26, ry: 0.13, op: 0.44 }, // Tharsis plateau
  { cx: -0.38, cy:  0.14, rx: 0.32, ry: 0.17, op: 0.40 }, // Valles Marineris
  { cx:  0.16, cy:  0.46, rx: 0.20, ry: 0.10, op: 0.32 },
  { cx: -0.16, cy: -0.52, rx: 0.17, ry: 0.08, op: 0.26 },
  { cx:  0.54, cy: -0.04, rx: 0.14, ry: 0.18, op: 0.22 },
  { cx: -0.24, cy:  0.56, rx: 0.26, ry: 0.10, op: 0.28 },
  { cx:  0.44, cy:  0.44, rx: 0.10, ry: 0.11, op: 0.18 },
  { cx: -0.04, cy:  0.22, rx: 0.34, ry: 0.05, op: 0.13 }, // equatorial rift
];

// ── Network routes as normalised cubic beziers ──────────────────────────
// All within unit circle; priority drives opacity and particle density
const ROUTES = [
  { p0:[-0.70,-0.20], cp1:[-0.14,-0.72], cp2:[ 0.28,-0.60], p1:[ 0.70,-0.14], pri:1.00 },
  { p0:[ 0.70,-0.14], cp1:[ 0.88, 0.10], cp2:[ 0.62, 0.46], p1:[ 0.32, 0.70], pri:0.70 },
  { p0:[-0.70,-0.20], cp1:[-0.48, 0.22], cp2:[-0.02, 0.56], p1:[ 0.32, 0.70], pri:0.50 },
  { p0:[-0.22, 0.74], cp1:[-0.02, 0.88], cp2:[ 0.40, 0.80], p1:[ 0.66, 0.54], pri:0.30 },
  { p0:[-0.58, 0.52], cp1:[-0.76,-0.04], cp2:[-0.80,-0.18], p1:[-0.70,-0.20], pri:0.42 },
  { p0:[ 0.02,-0.86], cp1:[ 0.36,-0.46], cp2:[ 0.58, 0.12], p1:[ 0.32, 0.70], pri:0.80 },
];

// ── Orbital rings (warm white, NOT blue — Mars brand only) ──────────────
const ORBITS = [
  { rx: R*1.27, ry: R*0.31, spd: 9.0e-4, dash: [8,14], lw: 1.10 },
  { rx: R*1.62, ry: R*0.50, spd: 5.2e-4, dash: [5,22], lw: 0.85 },
  { rx: R*1.90, ry: R*0.74, spd: 2.6e-4, dash: [3,30], lw: 0.60 },
];

// ── Visual parameters per network state ─────────────────────────────────
// br=brightness  ra=routeAlpha  ps=particleSpeed  ai=atmoIntensity
// oa=orbitAlpha  ml=ML monogram phase  warn=warning flavour
const PARAMS = {
  offline:    { br:0.35, ra:0.00, ps:0.00, ai:0.20, oa:0.10, ml:0.00, warn:null      }, // Brightness increased from 0.09
  connecting: { br:0.28, ra:0.18, ps:0.14, ai:0.28, oa:0.20, ml:0.04, warn:null      },
  connected:  { br:0.68, ra:0.68, ps:1.00, ai:0.66, oa:0.56, ml:0.10, warn:null      },
  excellent:  { br:1.00, ra:1.00, ps:1.50, ai:1.00, oa:0.86, ml:0.20, warn:null      },
  warning:    { br:0.58, ra:0.78, ps:0.58, ai:0.54, oa:0.46, ml:0.08, warn:'latency' },
  critical:   { br:0.46, ra:0.80, ps:0.26, ai:0.40, oa:0.32, ml:0.06, warn:'loss'   },
};

// ── Pure helpers ─────────────────────────────────────────────────────────
const lerp = (a, b, t) => a + (b - a) * t;

function bzPt(route, t) {
  const { p0, cp1, cp2, p1 } = route;
  const mt = 1 - t;
  return [
    mt*mt*mt*p0[0]+3*mt*mt*t*cp1[0]+3*mt*t*t*cp2[0]+t*t*t*p1[0],
    mt*mt*mt*p0[1]+3*mt*mt*t*cp1[1]+3*mt*t*t*cp2[1]+t*t*t*p1[1],
  ];
}

// ── Draw: Mars sphere (called each frame) ────────────────────────────────
function drawSphere(ctx, time, br, mlPhase) {
  const rot = time * 0.0016;         // full revolution ≈ 65 min — subtle life
  const ca = Math.cos(rot), sa = Math.sin(rot);

  // 3D volumetric sphere: off-centre radial gradient gives top-left specular
  const hx = CX - R * 0.28, hy = CY - R * 0.30;
  const bg = ctx.createRadialGradient(hx, hy, 0, CX, CY, R);
  bg.addColorStop(0.00, '#df7642'); bg.addColorStop(0.18, '#c45526');
  bg.addColorStop(0.40, '#9c3b1c'); bg.addColorStop(0.60, '#6a2110');
  bg.addColorStop(0.80, '#360d05'); bg.addColorStop(1.00, '#0c0302');
  ctx.beginPath(); ctx.arc(CX, CY, R, 0, Math.PI * 2);
  ctx.fillStyle = bg; ctx.fill();

  // Clipped terrain + ML monogram (inside sphere boundary)
  ctx.save();
  ctx.beginPath(); ctx.arc(CX, CY, R, 0, Math.PI * 2); ctx.clip();

  // Terrain features (slowly rotating)
  TERRAIN.forEach(f => {
    const rx = f.cx * ca - f.cy * sa;
    const ry = f.cx * sa + f.cy * ca;
    ctx.save();
    ctx.translate(CX + rx * R, CY + ry * R);
    ctx.scale(f.rx * R, f.ry * R);
    const tg = ctx.createRadialGradient(0, 0, 0, 0, 0, 1);
    tg.addColorStop(0.0, `rgba(20,5,1,${f.op})`);
    tg.addColorStop(0.6, `rgba(15,3,1,${f.op * 0.32})`);
    tg.addColorStop(1.0, 'rgba(0,0,0,0)');
    ctx.beginPath(); ctx.arc(0, 0, 1, 0, Math.PI * 2);
    ctx.fillStyle = tg; ctx.fill();
    ctx.restore();
  });

  // ML monogram — etched into terrain, visible only when connected
  if (mlPhase > 0.01) {
    const alpha = mlPhase * 0.22;
    // Precise pixel coordinates for ML inside clipped sphere
    const mh = R * 0.35, mw = R * 0.28, lw = R * 0.20, gap = R * 0.08;
    const totalW = mw + gap + lw;
    const mx = CX - totalW * 0.48;       // left edge of M
    const my = CY + R * 0.06 - mh / 2;  // top edge (slightly below centre)

    ctx.strokeStyle = `rgba(240,200,170,${alpha})`;
    ctx.lineWidth = 1.3; ctx.lineCap = 'round'; ctx.lineJoin = 'round';
    ctx.shadowBlur = 12 * mlPhase; ctx.shadowColor = `rgba(180,60,30,${alpha * 1.2})`;

    // M
    ctx.beginPath();
    ctx.moveTo(mx,          my + mh);          // bottom-left
    ctx.lineTo(mx,          my);               // top-left
    ctx.lineTo(mx + mw*0.5, my + mh * 0.42);  // centre dip
    ctx.lineTo(mx + mw,     my);               // top-right
    ctx.lineTo(mx + mw,     my + mh);          // bottom-right
    ctx.stroke();

    // L
    const lx = mx + mw + gap;
    ctx.beginPath();
    ctx.moveTo(lx,      my);          // top
    ctx.lineTo(lx,      my + mh);     // bottom
    ctx.lineTo(lx + lw, my + mh);     // foot
    ctx.stroke();

    ctx.shadowBlur = 0;
  }

  // Night-side terminator (right → dark)
  const sh = ctx.createLinearGradient(CX - R, CY, CX + R, CY);
  sh.addColorStop(0.00, 'rgba(0,0,0,0)');   sh.addColorStop(0.42, 'rgba(0,0,0,0)');
  sh.addColorStop(0.68, 'rgba(0,0,0,0.26)'); sh.addColorStop(1.00, 'rgba(0,0,0,0.72)');
  ctx.fillStyle = sh; ctx.fillRect(CX - R, CY - R, R * 2, R * 2);

  ctx.restore(); // end terrain/ML clip

  // Brightness dimming overlay — dims the entire sphere surface together with terrain and ML
  const dim = Math.max(0, 1 - br);
  if (dim > 0.01) {
    ctx.beginPath(); ctx.arc(CX, CY, R, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(6,8,14,${dim * 0.94})`; ctx.fill();
  }
}

// ── Draw: Orbital ring half (front or back of planet) ────────────────────
function drawOrbitHalf(ctx, orb, oa, nodeAngle, front) {
  if (oa < 0.01) return;
  ctx.save(); ctx.translate(CX, CY);

  // Only the matching arc half (occlusion trick)
  const startA = front ? 0       : Math.PI;
  const endA   = front ? Math.PI : Math.PI * 2;
  const alpha  = front ? oa * 0.40 : oa * 0.10;

  ctx.beginPath();
  ctx.ellipse(0, 0, orb.rx, orb.ry, 0, startA, endA);
  // Warm white rings — no blue
  ctx.strokeStyle = `rgba(225,198,174,${alpha})`;
  ctx.lineWidth   = orb.lw;
  ctx.setLineDash(orb.dash); ctx.stroke(); ctx.setLineDash([]);

  // Orbital node (satellite)
  const nx = orb.rx * Math.cos(nodeAngle);
  const ny = orb.ry * Math.sin(nodeAngle);
  const nodeFront = ny >= 0;          // bottom of canvas = near side

  if (nodeFront === front) {
    const pulse = 0.70 + 0.30 * Math.sin(nodeAngle * 2.8);
    const na = oa * pulse;
    const ng = ctx.createRadialGradient(nx, ny, 0, nx, ny, 10);
    ng.addColorStop(0.0, `rgba(238,200,164,${na * 0.60})`);
    ng.addColorStop(0.4, `rgba(210,170,130,${na * 0.22})`);
    ng.addColorStop(1.0, 'rgba(0,0,0,0)');
    ctx.beginPath(); ctx.arc(nx, ny, 10, 0, Math.PI * 2);
    ctx.fillStyle = ng; ctx.fill();

    ctx.beginPath(); ctx.arc(nx, ny, 2.2, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(245,220,195,${na})`;
    ctx.shadowBlur = 7; ctx.shadowColor = 'rgba(190,110,70,0.8)';
    ctx.fill(); ctx.shadowBlur = 0;
  }
  ctx.restore();
}

// ── Draw: Connection energy beam (planet bottom → canvas edge) ───────────
function drawBeam(ctx, alpha) {
  if (alpha < 0.02) return;
  const x = CX, y1 = CY + R + 2, y2 = H - 2;

  // Glow column
  const g1 = ctx.createLinearGradient(0, y1, 0, y2);
  g1.addColorStop(0.0, `rgba(195,58,28,${alpha * 0.46})`);
  g1.addColorStop(0.6, `rgba(155,38,18,${alpha * 0.18})`);
  g1.addColorStop(1.0, `rgba(115,28,12,${alpha * 0.04})`);
  ctx.beginPath(); ctx.moveTo(x, y1); ctx.lineTo(x, y2);
  ctx.strokeStyle = g1; ctx.lineWidth = 16; ctx.lineCap = 'round'; ctx.stroke();

  // Core
  const g2 = ctx.createLinearGradient(0, y1, 0, y2);
  g2.addColorStop(0.0, `rgba(255,172,130,${alpha * 0.88})`);
  g2.addColorStop(0.5, `rgba(218,88,48,${alpha * 0.42})`);
  g2.addColorStop(1.0, `rgba(165,45,20,${alpha * 0.08})`);
  ctx.beginPath(); ctx.moveTo(x, y1); ctx.lineTo(x, y2);
  ctx.strokeStyle = g2; ctx.lineWidth = 1.4;
  ctx.shadowBlur = 12; ctx.shadowColor = `rgba(195,55,25,0.8)`;
  ctx.stroke(); ctx.shadowBlur = 0;

  // Impact corona where beam meets planet
  const ig = ctx.createRadialGradient(CX, CY + R, 0, CX, CY + R, 32);
  ig.addColorStop(0.0, `rgba(255,170,120,${alpha * 0.60})`);
  ig.addColorStop(0.5, `rgba(195,60,25,${alpha * 0.24})`);
  ig.addColorStop(1.0, 'rgba(0,0,0,0)');
  ctx.beginPath(); ctx.arc(CX, CY + R, 32, 0, Math.PI * 2);
  ctx.fillStyle = ig; ctx.fill();
}

// ══════════════════════════════════════════════════════════════════════════
//  LIVING MARS COMPONENT
// ══════════════════════════════════════════════════════════════════════════
export function LivingMars({ state = 'offline' }: { state?: string }) {
  const canvasRef = useRef(null);
  const rafRef    = useRef(null);
  const prevNow   = useRef(null);
  const stateRef  = useRef(state);

  // Lerped visual params (mutated in RAF — no re-render)
  const cur  = useRef({ ...PARAMS.offline, ml: 0 });
  // Warning oscillator
  const warn = useRef({ phase: 0, intensity: 0 });
  // Beam phase — animated internally when connecting
  const beam = useRef({ v: 0 });

  // 20 data-flow particles across 6 routes, staggered
  const parts = useRef(
    Array.from({ length: 20 }, (_, i) => ({
      ri:  i % ROUTES.length,
      t:   i / 20,
      spd: 8e-4 + (i % 7) * 2e-4,
      sz:  1.5  + (i % 5) * 0.44,
      op:  0.46 + (i % 3) * 0.22,
    }))
  );

  useEffect(() => { stateRef.current = state; }, [state]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    // Very subtle scanline texture (depth without CRT feel)
    const scan = document.createElement('canvas');
    scan.width = 2; scan.height = 4;
    const sc = scan.getContext('2d');
    sc.fillStyle = 'rgba(0,0,0,0.028)'; sc.fillRect(0, 0, 2, 1);
    const scanPat = ctx.createPattern(scan, 'repeat');

    function frame(now) {
      const dt = prevNow.current !== null ? Math.min(now - prevNow.current, 28) : 16;
      prevNow.current = now;
      const time = now * 0.001;   // seconds

      const s   = stateRef.current;
      const tgt = PARAMS[s] ?? PARAMS.offline;
      const c   = cur.current;
      const w   = warn.current;

      // ── Lerp all visual params (~1.6 s transition) ──────────────────
      const LF = 0.020;
      c.br = lerp(c.br, tgt.br, LF); c.ra = lerp(c.ra, tgt.ra, LF);
      c.ps = lerp(c.ps, tgt.ps, LF); c.ai = lerp(c.ai, tgt.ai, LF);
      c.oa = lerp(c.oa, tgt.oa, LF); c.ml = lerp(c.ml, tgt.ml, LF);
      c.warn = tgt.warn;

      // ── Connection beam (only during 'connecting') ───────────────────
      if (s === 'connecting') {
        beam.current.v = Math.min(1, beam.current.v + dt / 2200);
      } else {
        beam.current.v = Math.max(0, beam.current.v - dt / 800);
      }
      const beamA = s === 'connecting'
        ? beam.current.v * (0.45 + 0.55 * Math.abs(Math.sin(time * 2.6)))
        : beam.current.v;

      // ── Warning oscillator ───────────────────────────────────────────
      const pspd = c.warn === 'loss' ? 0.0044 : 0.0028;
      if (c.warn) { w.phase += dt * pspd; w.intensity = lerp(w.intensity, 1.0, 0.055); }
      else         {                        w.intensity = lerp(w.intensity, 0.0, 0.038); }
      const wPulse = w.intensity > 0.02 ? w.intensity * Math.abs(Math.sin(w.phase)) : 0;

      // ── Route colour: cream → amber (latency) → mars-red (loss) ─────
      // No blue anywhere. Warm palette only.
      let rR, rG, rB;
      if      (c.warn === 'loss')    { rR=218; rG=72;  rB=56; }
      else if (c.warn === 'latency') { rR=204; rG=142; rB=46; }
      else if (s === 'excellent')    { rR=252; rG=228; rB=206; }
      else                           { rR=236; rG=188; rB=154; }
      const rgb   = `${rR},${rG},${rB}`;
      const glow  = c.warn === 'loss'    ? 'rgba(175,36,26,0.9)'
                  : c.warn === 'latency' ? 'rgba(165,90,18,0.9)'
                  :                        'rgba(155,54,24,0.9)';

      // ── Dynamic route priorities (simulate intelligent path selection)
      const rPri = ROUTES.map((rt, i) =>
        rt.pri * (0.82 + 0.18 * Math.sin(time * 0.09 + i * 1.4))
      );

      // ═══════════════════════════════════════════════════════════════

      // 1 ── Deep space background
      ctx.fillStyle = T.space; ctx.fillRect(0, 0, W, H);

      // 2 ── Stars (restrained twinkle)
      STARS.forEach(st => {
        const tw = 0.90 + 0.10 * Math.sin(time * 1.05 + st.ph);
        ctx.beginPath(); ctx.arc(st.x, st.y, st.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(208,222,240,${st.a * tw * 0.76})`; ctx.fill();
      });

      // 3 ── Outer atmospheric corona (Mars red — two-layer)
      {
        const ai = c.ai;
        const g1 = ctx.createRadialGradient(CX,CY,R*0.87,CX,CY,R*3.0);
        g1.addColorStop(0.0, `rgba(184,76,32,${0.16*ai})`);
        g1.addColorStop(0.35,`rgba(156,58,22,${0.07*ai})`);
        g1.addColorStop(1.0, 'rgba(0,0,0,0)');
        ctx.beginPath(); ctx.arc(CX,CY,R*3.0,0,Math.PI*2); ctx.fillStyle=g1; ctx.fill();

        const g2 = ctx.createRadialGradient(CX,CY,R*0.93,CX,CY,R*1.36);
        g2.addColorStop(0.0, `rgba(200,86,36,${0.23*ai})`);
        g2.addColorStop(0.65,`rgba(176,66,24,${0.09*ai})`);
        g2.addColorStop(1.0, 'rgba(0,0,0,0)');
        ctx.beginPath(); ctx.arc(CX,CY,R*1.36,0,Math.PI*2); ctx.fillStyle=g2; ctx.fill();
      }

      // 4 ── Back orbital rings (behind planet)
      ORBITS.forEach((orb,i)=>drawOrbitHalf(ctx,orb,c.oa,time*orb.spd*1000+i*2.1,false));

      // 5 ── Mars sphere (with ML monogram inside)
      drawSphere(ctx, time, c.br, c.ml);

      // 6 ── Surface network routes (clipped to Mars disk)
      if (c.ra > 0.01) {
        ctx.save();
        ctx.beginPath(); ctx.arc(CX,CY,R*0.97,0,Math.PI*2); ctx.clip();

        ROUTES.forEach((route, ri) => {
          const x0  = CX + route.p0[0]*R,   y0  = CY + route.p0[1]*R;
          const cx1 = CX + route.cp1[0]*R,  cy1 = CY + route.cp1[1]*R;
          const cx2 = CX + route.cp2[0]*R,  cy2 = CY + route.cp2[1]*R;
          const x1  = CX + route.p1[0]*R,   y1  = CY + route.p1[1]*R;

          const rp = rPri[ri];
          const ra = c.ra * rp * (1 + 0.20 * Math.sin(w.phase * 1.3 + ri * 0.85) * w.intensity);

          // Wide glow pass
          ctx.beginPath(); ctx.moveTo(x0,y0); ctx.bezierCurveTo(cx1,cy1,cx2,cy2,x1,y1);
          ctx.strokeStyle=`rgba(${rgb},${ra*0.09})`; ctx.lineWidth=13; ctx.lineCap='round';
          ctx.shadowBlur=0; ctx.stroke();

          // Core line with bloom — CREAM on RED PLANET (the signature look)
          ctx.beginPath(); ctx.moveTo(x0,y0); ctx.bezierCurveTo(cx1,cy1,cx2,cy2,x1,y1);
          ctx.strokeStyle=`rgba(${rgb},${ra*0.76})`; ctx.lineWidth=1.2;
          ctx.shadowBlur=8; ctx.shadowColor=glow; ctx.stroke(); ctx.shadowBlur=0;

          // Endpoint beacon nodes
          [[x0,y0],[x1,y1]].forEach(([ex,ey]) => {
            ctx.beginPath(); ctx.arc(ex,ey,2.8,0,Math.PI*2);
            ctx.fillStyle=`rgba(${rgb},${c.ra*rp*0.86})`;
            ctx.shadowBlur=12; ctx.shadowColor=glow; ctx.fill(); ctx.shadowBlur=0;
          });
        });
        ctx.restore();
      }

      // 7 ── Data flow particles (clipped, cream-white heads with trail)
      if (c.ps > 0.01) {
        ctx.save();
        ctx.beginPath(); ctx.arc(CX,CY,R*0.97,0,Math.PI*2); ctx.clip();

        parts.current.forEach(p => {
          p.t = (p.t + p.spd * c.ps * (dt / 16)) % 1;
          const rp = rPri[p.ri];
          if (rp < 0.18) return;  // skip low-priority route particles

          const [bx, by] = bzPt(ROUTES[p.ri], p.t);
          const px = CX + bx * R, py = CY + by * R;

          // Trail (5% behind head)
          const [tx, ty] = bzPt(ROUTES[p.ri], ((p.t - 0.052) % 1 + 1) % 1);
          ctx.beginPath(); ctx.arc(CX+tx*R, CY+ty*R, p.sz*0.36, 0, Math.PI*2);
          ctx.fillStyle=`rgba(${rgb},${c.ra*p.op*rp*0.24})`; ctx.fill();

          // Head
          ctx.beginPath(); ctx.arc(px, py, p.sz, 0, Math.PI*2);
          ctx.fillStyle=`rgba(${rgb},${c.ra*p.op*rp})`;
          ctx.shadowBlur=10; ctx.shadowColor=glow; ctx.fill(); ctx.shadowBlur=0;
        });
        ctx.restore();
      }

      // 8 ── Atmospheric limb haze (softens sphere edge)
      {
        const ai = c.ai;
        const lg = ctx.createRadialGradient(CX,CY,R*0.77,CX,CY,R*1.09);
        lg.addColorStop(0.0,'rgba(0,0,0,0)');
        lg.addColorStop(0.5,`rgba(190,84,35,${0.10*ai})`);
        lg.addColorStop(1.0,`rgba(210,104,46,${0.24*ai})`);
        ctx.beginPath(); ctx.arc(CX,CY,R*1.09,0,Math.PI*2);
        ctx.fillStyle=lg; ctx.fill();
      }

      // 9 ── Front orbital rings (in front of planet)
      ORBITS.forEach((orb,i)=>drawOrbitHalf(ctx,orb,c.oa,time*orb.spd*1000+i*2.1,true));

      // 10 ── EXCELLENT: premium warm white-rose corona
      if (s === 'excellent' && c.br > 0.5) {
        const ep = 0.52 + 0.48 * Math.sin(time * 0.64);
        const it  = Math.min(1, (c.br - 0.5) / 0.5);
        const eg = ctx.createRadialGradient(CX,CY,R*0.95,CX,CY,R*1.85);
        eg.addColorStop(0.0,`rgba(255,215,192,${0.16*it*ep})`);
        eg.addColorStop(0.5,`rgba(238,148,108,${0.07*it*ep})`);
        eg.addColorStop(1.0,'rgba(0,0,0,0)');
        ctx.beginPath(); ctx.arc(CX,CY,R*1.85,0,Math.PI*2);
        ctx.fillStyle=eg; ctx.fill();
      }

      // 11 ── Warning / loss pulse ring (amber or mars-red — no blue-red)
      if (wPulse > 0.02) {
        const wc = c.warn === 'loss' ? '204,36,36' : '196,145,35';
        const wg = ctx.createRadialGradient(CX,CY,R*0.85,CX,CY,R*1.62);
        wg.addColorStop(0.00,`rgba(${wc},${0.03*wPulse})`);
        wg.addColorStop(0.42,`rgba(${wc},${0.10*wPulse})`);
        wg.addColorStop(1.00,'rgba(0,0,0,0)');
        ctx.beginPath(); ctx.arc(CX,CY,R*1.62,0,Math.PI*2);
        ctx.fillStyle=wg; ctx.fill();
      }

      // 12 ── Connection beam (MARSTART MOMENT: button → planet)
      if (beamA > 0.02) drawBeam(ctx, beamA);

      // 13 ── Scanline depth texture (barely perceptible)
      ctx.fillStyle = scanPat; ctx.fillRect(0, 0, W, H);

      rafRef.current = requestAnimationFrame(frame);
    }

    rafRef.current = requestAnimationFrame(frame);
    return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current); };
  }, []); // intentionally empty — state changes via stateRef only

  return (
    <canvas
      ref={canvasRef}
      width={W}
      height={H}
      style={{ display: 'block' }}
    />
  );
}
