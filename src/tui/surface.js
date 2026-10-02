import { stripVTControlCharacters } from 'node:util';

const segments = new Intl.Segmenter(undefined, { granularity: 'grapheme' });
export const sanitize = value => stripVTControlCharacters(String(value ?? '')).replace(/\p{Cc}/gu, ' ');
const cells = text => /\p{Extended_Pictographic}|[\u1100-\u115f\u2329\u232a\u2e80-\ua4cf\uac00-\ud7a3\uf900-\ufaff\ufe10-\ufe19\ufe30-\ufe6f\uff00-\uff60]/u.test(text) ? 2 : /^\p{Mark}+$/u.test(text) ? 0 : 1;
export const textWidth = value => [...segments.segment(sanitize(value))].reduce((size, item) => size + cells(item.segment), 0);
export function clip(value, width, ellipsis = false) {
  const text = sanitize(value), limit = Math.max(0, width);
  if (textWidth(text) <= limit) return text;
  let result = '', size = 0;
  for (const { segment } of segments.segment(text)) {
    if (size + cells(segment) > limit - (ellipsis ? 1 : 0)) break;
    result += segment; size += cells(segment);
  }
  return result + (ellipsis && limit ? '…' : '');
}
export function tail(value, width) {
  const parts = [...segments.segment(sanitize(value))].map(item => item.segment);
  let size = parts.reduce((sum, part) => sum + cells(part), 0);
  while (parts.length && size > Math.max(0, width)) size -= cells(parts.shift());
  return parts.join('');
}
export function wrapText(value, width) {
  const limit = Math.max(1, width), lines = [];
  for (const source of String(value ?? '').split(/\r?\n|\r/)) {
    let line = '', size = 0;
    for (const word of sanitize(source).split(/(\s+)/)) {
      if (size && size + textWidth(word) > limit) { lines.push(line.trimEnd()); line = ''; size = 0; }
      for (const { segment } of segments.segment(word)) {
        const length = cells(segment);
        if (size + length > limit) { lines.push(line); line = ''; size = 0; }
        if (!size && segment === ' ') continue;
        line += segment; size += length;
      }
    }
    lines.push(line);
  }
  return lines;
}

// One coordinated palette per theme. Status colours supplement readable status labels.
export const THEMES = [
  { name: 'Obsidian', bg: '#111416', panel: '#191d20', raised: '#23292c', border: '#3b4346', text: '#eeeae2', muted: '#a4afaf',
    subtle: '#747f81', accent: '#dcc399', onAccent: '#1c1b18', good: '#a5c8ae', warn: '#e2bd83', bad: '#e79d99', info: '#aabed4' },
  { name: 'Midnight', bg: '#10131e', panel: '#191e2c', raised: '#242c3d', border: '#3c4760', text: '#e8ecf7', muted: '#aab6cc',
    subtle: '#7d8ba5', accent: '#bbb6f4', onAccent: '#181729', good: '#93d0c7', warn: '#e4c091', bad: '#eea5b1', info: '#a6c6ed' },
  { name: 'Porcelain', bg: '#ece8e0', panel: '#f7f4ee', raised: '#e5e0d6', border: '#b8b0a1', text: '#2f3434', muted: '#58615e',
    subtle: '#72786e', accent: '#765833', onAccent: '#fffaf0', good: '#38664e', warn: '#855b1d', bad: '#9a403e', info: '#426585' },
];

const rgb = color => [1, 3, 5].map(at => parseInt(color.slice(at, at + 2), 16));
const mix = (first, second, ratio) => '#' + rgb(first).map((n, index) => Math.round(n * ratio + rgb(second)[index] * (1 - ratio)).toString(16).padStart(2, '0')).join('');

/** Cell-based drawing keeps ANSI styling outside all layout and mouse-coordinate calculations. */
export class Surface {
  constructor(width, height, theme) {
    this.width = width; this.height = height; this.theme = theme;
    this.grid = Array.from({ length: height }, () => Array.from({ length: width }, () => ({ char: ' ', fg: theme.text, bg: theme.bg, bold: false })));
  }
  fill(x, y, width, height, bg = this.theme.panel) {
    for (let row = Math.max(0, y); row < Math.min(this.height, y + height); row++)
      for (let col = Math.max(0, x); col < Math.min(this.width, x + width); col++) this.grid[row][col] = { char: ' ', fg: this.theme.text, bg, bold: false };
  }
  text(x, y, value, { fg = this.theme.text, bg, bold = false, width = this.width - x } = {}) {
    if (y < 0 || y >= this.height) return;
    let col = x;
    for (const { segment } of segments.segment(clip(value, width))) {
      const size = cells(segment);
      if (!size || col < 0 || col + size > this.width) continue;
      const background = bg || this.grid[y][col].bg;
      this.grid[y][col] = { char: segment, fg, bg: background, bold };
      if (size === 2) this.grid[y][col + 1] = { char: '', fg, bg: background, bold };
      col += size;
    }
  }
  panel(x, y, width, height, { title, subtitle, focus = false, bg = this.theme.panel, border = this.theme.border } = {}) {
    if (width < 4 || height < 3) return;
    this.fill(x, y, width, height, bg);
    const color = focus ? this.theme.accent : border;
    this.text(x, y, '╭' + '─'.repeat(width - 2) + '╮', { fg: color });
    this.text(x, y + height - 1, '╰' + '─'.repeat(width - 2) + '╯', { fg: color });
    for (let row = y + 1; row < y + height - 1; row++) {
      this.text(x, row, '│', { fg: color }); this.text(x + width - 1, row, '│', { fg: color });
    }
    if (title) this.text(x + 2, y, ` ${clip(title, width - 7, true)} `, { fg: focus ? this.theme.accent : this.theme.muted, bold: true });
    if (subtitle && width > textWidth(title || '') + textWidth(subtitle) + 10)
      this.text(x + width - textWidth(subtitle) - 3, y, ` ${subtitle} `, { fg: this.theme.subtle });
  }
  dim() {
    for (const row of this.grid) for (const cell of row) {
      cell.fg = mix(cell.fg, this.theme.bg, 0.35); cell.bg = mix(cell.bg, this.theme.bg, 0.55); cell.bold = false;
    }
  }
  lines(color = true) {
    if (!color) return this.grid.map(row => row.map(cell => cell.char).join(''));
    return this.grid.map(row => {
      let style = '', line = '';
      for (const cell of row) {
        const key = `${cell.fg}/${cell.bg}/${cell.bold}`;
        if (style !== key) {
          line += `\x1b[0;${cell.bold ? '1;' : ''}38;2;${rgb(cell.fg).join(';')};48;2;${rgb(cell.bg).join(';')}m`; style = key;
        }
        line += cell.char;
      }
      return line + '\x1b[0m';
    });
  }
}
