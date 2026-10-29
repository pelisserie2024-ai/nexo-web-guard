'use strict';
/** Interpretación mínima de robots.txt para el agente "NexoWebGuard" y el comodín "*". */

const AGENT = 'nexowebguard';

function parseGroups(text) {
  const groups = [];
  let cur = null;
  let lastWasAgent = false;
  String(text || '').split(/\r?\n/).slice(0, 2000).forEach((line) => {
    const clean = line.replace(/#.*$/, '').trim();
    if (!clean) return;
    const m = clean.match(/^([A-Za-z-]+)\s*:\s*(.*)$/);
    if (!m) return;
    const key = m[1].toLowerCase();
    const val = m[2].trim();
    if (key === 'user-agent') {
      if (!cur || !lastWasAgent) {
        cur = { agents: [], rules: [] };
        groups.push(cur);
      }
      cur.agents.push(val.toLowerCase());
      lastWasAgent = true;
    } else if ((key === 'disallow' || key === 'allow') && cur) {
      cur.rules.push({ allow: key === 'allow', path: val });
      lastWasAgent = false;
    } else {
      lastWasAgent = false;
    }
  });
  return groups;
}

function ruleMatches(rulePath, path) {
  if (!rulePath) return false;
  let re = rulePath.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  const anchored = re.endsWith('\\$');
  if (anchored) re = re.slice(0, -2) + '$';
  return new RegExp('^' + re).test(path);
}

/** true si el agente puede consultar `path`. */
function robotsAllows(text, path) {
  const groups = parseGroups(text);
  let group = groups.find((g) => g.agents.includes(AGENT));
  if (!group) group = groups.find((g) => g.agents.includes('*'));
  if (!group) return true;
  let best = null;
  group.rules.forEach((r) => {
    if (!r.path) return; // "Disallow:" vacío = permitido todo
    if (ruleMatches(r.path, path)) {
      if (!best || r.path.length > best.path.length || (r.path.length === best.path.length && r.allow)) best = r;
    }
  });
  return best ? best.allow : true;
}

module.exports = { robotsAllows, parseGroups };
