#!/usr/bin/env node
/**
 * Renders a benchmark report from scripts/bench.mjs as a static SVG bar chart
 * (light/dark aware) for the README.
 *
 * Usage: node scripts/render-bench-chart.mjs <report.json> <out.svg>
 */
import { readFileSync, writeFileSync } from 'node:fs';

const [reportPath, outPath] = process.argv.slice(2);
if (!reportPath || !outPath) throw new Error('usage: render-bench-chart.mjs <report.json> <out.svg>');
const report = JSON.parse(readFileSync(reportPath, 'utf8'));

const rows = report.results.flatMap((r) =>
  ['Pack', 'Unpack'].map((op) => ({
    label: `${r.curve} ${r.mode} · ${op.toLowerCase()}`,
    ts: r.opsPerSec[`ts${op}`].median,
    rust: r.opsPerSec[`rust${op}`].median,
  })),
);

const W = 820;
const LEFT = 210;
const RIGHT = 120;
const TOP = 96;
const BAR = 12;
const GAP = 2;
const GROUP = BAR * 2 + GAP + 18;
const H = TOP + rows.length * GROUP + 52;
const max = Math.ceil(Math.max(...rows.flatMap((r) => [r.ts, r.rust])) / 1000) * 1000;
const x = (v) => LEFT + (v / max) * (W - LEFT - RIGHT);
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;');

function bar(x0, y, value, cls) {
  const w = Math.max(x(value) - x0, 4);
  // Square at the baseline, 4px rounded at the data end.
  return `<path class="${cls}" d="M${x0},${y} h${w - 4} a4,4 0 0 1 4,4 v${BAR - 8} a4,4 0 0 1 -4,4 h${-(w - 4)} z"><title>${esc(value.toLocaleString('en-US'))} ops/s</title></path>`;
}

const ticks = [];
for (let v = 0; v <= max; v += max / 4) {
  ticks.push(
    `<line class="grid" x1="${x(v)}" x2="${x(v)}" y1="${TOP - 8}" y2="${H - 44}"/>` +
      `<text class="muted" x="${x(v)}" y="${H - 26}" text-anchor="middle">${v.toLocaleString('en-US')}</text>`,
  );
}

const groups = rows.map((r, i) => {
  const y = TOP + i * GROUP;
  const ratio = r.ts / r.rust;
  return [
    `<text class="secondary" x="${LEFT - 12}" y="${y + BAR + 4}" text-anchor="end">${esc(r.label)}</text>`,
    bar(LEFT, y, r.ts, 'ts'),
    bar(LEFT, y + BAR + GAP, r.rust, 'rust'),
    `<text class="primary" x="${x(Math.max(r.ts, r.rust)) + 8}" y="${y + BAR + 4}">${ratio.toFixed(1)}× ${ratio >= 1 ? 'faster' : 'slower'}</text>`,
  ].join('');
});

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-labelledby="t d" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif" font-size="12">
<title id="t">didcomm-ts vs didcomm-rust (WASM) throughput</title>
<desc id="d">Median operations per second for pack and unpack, ${report.messageBytes}-byte messages, ${esc(report.cpu)}, Node ${esc(report.node)}. ${rows.map((r) => `${r.label}: didcomm-ts ${r.ts}, didcomm-rust ${r.rust}`).join('; ')}.</desc>
<style>
  .bg { fill: #fcfcfb } .primary { fill: #0b0b0b } .secondary { fill: #52514e } .muted { fill: #898781 }
  .grid { stroke: #e1e0d9; stroke-width: 1 } .ts { fill: #2a78d6 } .rust { fill: #eb6834 }
  @media (prefers-color-scheme: dark) {
    .bg { fill: #1a1a19 } .primary { fill: #ffffff } .secondary { fill: #c3c2b7 }
    .grid { stroke: #2c2c2a } .ts { fill: #3987e5 } .rust { fill: #d95926 }
  }
</style>
<rect class="bg" width="${W}" height="${H}" rx="8"/>
<text class="primary" x="24" y="34" font-size="16" font-weight="600">Throughput: didcomm-ts vs didcomm-rust (WASM)</text>
<text class="secondary" x="24" y="54">Median ops/s, higher is better · ${report.messageBytes}-byte message · ${esc(report.cpu)} · Node ${esc(report.node)}</text>
<rect class="ts" x="24" y="68" width="12" height="12" rx="2"/><text class="secondary" x="42" y="78">didcomm-ts</text>
<rect class="rust" x="130" y="68" width="12" height="12" rx="2"/><text class="secondary" x="148" y="78">didcomm-rust (WASM)</text>
${ticks.join('\n')}
${groups.join('\n')}
<text class="muted" x="${(LEFT + W - RIGHT) / 2}" y="${H - 8}" text-anchor="middle">operations per second</text>
</svg>
`;
writeFileSync(outPath, svg);
console.log(`wrote ${outPath}`);
