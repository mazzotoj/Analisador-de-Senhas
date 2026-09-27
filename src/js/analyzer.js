/**
 * analyzer.js — Estimador de força de senhas baseado em padrões.
 *
 * Em vez de apenas contar tipos de caracteres, o estimador procura padrões
 * que um atacante testaria primeiro (senhas comuns, palavras, substituições
 * "l33t", sequências, repetições, padrões de teclado e datas) e calcula o
 * número mínimo de tentativas necessárias para adivinhar a senha, usando
 * programação dinâmica sobre as combinações de padrões encontradas.
 * A abordagem é inspirada no zxcvbn (Wheeler, 2016), em versão simplificada.
 *
 * Todo o processamento acontece localmente, no navegador.
 */
import { COMMON_PASSWORDS } from './data/common-passwords.js';
import { WORDLIST_PT } from './data/wordlist-pt.js';
import { WORDLIST_EN } from './data/wordlist-en.js';
import { WORDLIST_COMMON_PT } from './data/wordlist-common-pt.js';

const COMMON_RANK = new Map(COMMON_PASSWORDS.map((p, i) => [p, i + 1]));
const WORDS = new Set([...WORDLIST_PT, ...WORDLIST_EN, ...WORDLIST_COMMON_PT]);

/** Posição média estimada de uma palavra em um dicionário ordenado por frequência. */
export const WORD_GUESSES = 5000;
/**
 * Custo, por caractere, de trechos sem padrão reconhecido (log10(10) = 1).
 * Mesmo valor adotado pelo zxcvbn: trechos escolhidos por pessoas raramente
 * são tão imprevisíveis quanto o alfabeto completo sugere.
 */
export const BRUTEFORCE_CARDINALITY = 10;
/** Ano de referência para padrões de data. */
const REFERENCE_YEAR = 2026;

const LEET = { '4': ['a'], '@': ['a'], '3': ['e'], '1': ['i', 'l'], '!': ['i'], '0': ['o'],
  '$': ['s'], '5': ['s'], '7': ['t'], '+': ['t'], '8': ['b'], '9': ['g'], '2': ['z'] };

const KEYBOARD_PATTERNS = [
  '1234567890-=', 'qwertyuiop[]', "asdfghjkl;'", 'zxcvbnm,./',
  '1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p', 'zaq1xsw2cde3vfr4bgt5nhy6mju7',
  'qazwsxedcrfvtgbyhnujmikolp', '!@#$%^&*()_+', '147258369', '789456123', '159753', '963852741',
];

/** Cenários de ataque (tentativas por segundo). */
export const ATTACK_SCENARIOS = [
  { id: 'onlineThrottled', label: 'Ataque online com limite de tentativas', rate: 100 / 3600 },
  { id: 'onlineFast', label: 'Ataque online sem limite', rate: 10 },
  { id: 'offlineSlow', label: 'Offline, hash lento (bcrypt)', rate: 1e4 },
  { id: 'offlineFast', label: 'Offline, hash rápido (GPU)', rate: 1e10 },
];

export const SCORE_LABELS = ['Muito fraca', 'Fraca', 'Razoável', 'Forte', 'Muito forte'];

const log10 = Math.log10;

/** Tamanho do alfabeto (pool) correspondente às classes presentes na senha. */
export function charsetSize(password) {
  let n = 0;
  if (/[a-z]/.test(password)) n += 26;
  if (/[A-Z]/.test(password)) n += 26;
  if (/[0-9]/.test(password)) n += 10;
  if (/[^A-Za-z0-9]/.test(password)) n += 33;
  return n || 1;
}

/** Verificação de composição (informativa). */
export function compositionChecks(password) {
  return {
    minLength: password.length >= 8,
    recommendedLength: password.length >= 12,
    lower: /[a-z]/.test(password),
    upper: /[A-Z]/.test(password),
    digit: /[0-9]/.test(password),
    symbol: /[^A-Za-z0-9]/.test(password),
  };
}

function binom(n, k) {
  if (k > n) return 0;
  let r = 1;
  for (let i = 1; i <= k; i++) r = (r * (n - k + i)) / i;
  return r;
}

/** Variações de maiúsculas/minúsculas (log10). */
function uppercaseVariations(token) {
  if (!/[A-Z]/.test(token) || token.toLowerCase() === token) return 0;
  if (/^[A-Z][^A-Z]+$/.test(token) || /^[^a-z]+$/.test(token) || /^[^A-Z]+[A-Z]$/.test(token)) return log10(2);
  const U = (token.match(/[A-Z]/g) || []).length;
  const L = (token.match(/[a-z]/g) || []).length;
  let v = 0;
  for (let i = 1; i <= Math.min(U, L); i++) v += binom(U + L, i);
  return log10(Math.max(v, 2));
}

/** Gera variantes "des-l33t" de um token (limitado para manter o custo baixo). */
function unleetVariants(lower) {
  let variants = [''];
  let changed = false;
  for (const ch of lower) {
    const subs = LEET[ch];
    if (subs) {
      changed = true;
      const next = [];
      for (const v of variants) for (const s of subs) next.push(v + s);
      variants = next.slice(0, 16);
    } else {
      variants = variants.map((v) => v + ch);
    }
  }
  return changed ? variants : [];
}

function dictionaryMatches(password) {
  const matches = [];
  const n = password.length;
  const lowerAll = password.toLowerCase();
  for (let i = 0; i < n; i++) {
    for (let j = i + 2; j < n; j++) {
      const token = password.slice(i, j + 1);
      const lower = lowerAll.slice(i, j + 1);
      const whole = i === 0 && j === n - 1;
      const candidates = [{ word: lower, leet: false, reversed: false }];
      if (lower.length >= 4) candidates.push({ word: [...lower].reverse().join(''), leet: false, reversed: true });
      for (const v of unleetVariants(lower)) candidates.push({ word: v, leet: true, reversed: false });

      for (const c of candidates) {
        let base = null;
        let kind = null;
        const rank = COMMON_RANK.get(c.word);
        if (rank && (c.word.length >= 4 || whole)) { base = rank; kind = 'common'; }
        if (WORDS.has(c.word) && (base === null || WORD_GUESSES < base)) { base = WORD_GUESSES; kind = 'word'; }
        if (base === null) continue;
        let g = log10(Math.max(base, 1)) + uppercaseVariations(token);
        if (c.reversed) g += log10(2);
        if (c.leet) {
          const subs = [...lower].filter((ch) => LEET[ch]).length;
          g += log10(Math.max(2, 2 ** Math.min(subs, 4)));
        }
        matches.push({ type: 'dictionary', kind, i, j, token, matched: c.word,
          leet: c.leet, reversed: c.reversed, rank: kind === 'common' ? base : null, guessesLog10: g });
      }
    }
  }
  return matches;
}

function charClass(c) {
  if (/[a-z]/.test(c)) return 'lower';
  if (/[A-Z]/.test(c)) return 'upper';
  if (/[0-9]/.test(c)) return 'digit';
  return null;
}

function sequenceMatches(password) {
  const matches = [];
  const n = password.length;
  let i = 0;
  while (i < n - 2) {
    const cls = charClass(password[i]);
    const delta = password.charCodeAt(i + 1) - password.charCodeAt(i);
    if (!cls || Math.abs(delta) !== 1 || charClass(password[i + 1]) !== cls) { i++; continue; }
    let j = i + 1;
    while (j + 1 < n && charClass(password[j + 1]) === cls &&
      password.charCodeAt(j + 1) - password.charCodeAt(j) === delta) j++;
    if (j - i + 1 >= 3) {
      const first = password[i];
      const base = 'aAzZ019'.includes(first) ? 4 : cls === 'digit' ? 10 : 26;
      const len = j - i + 1;
      const g = log10(base * len * (delta < 0 ? 2 : 1));
      matches.push({ type: 'sequence', i, j, token: password.slice(i, j + 1), ascending: delta > 0, guessesLog10: g });
      i = j + 1;
    } else i++;
  }
  return matches;
}

function repeatMatches(password) {
  const matches = [];
  const seen = new Set();
  for (const re of [/(.+)\1+/g, /(.+?)\1+/g]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(password)) !== null) {
      const token = m[0];
      const base = m[1];
      const key = `${m.index}:${token.length}:${base}`;
      if (token.length >= 3 && !seen.has(key)) {
        seen.add(key);
        const baseGuesses = estimateGuessesLog10(base);
        const count = token.length / base.length;
        matches.push({ type: 'repeat', i: m.index, j: m.index + token.length - 1, token, base, count,
          guessesLog10: baseGuesses + log10(count) });
      }
      if (m[0].length === 0) re.lastIndex++;
    }
  }
  return matches;
}

function keyboardMatches(password) {
  const matches = [];
  const lower = password.toLowerCase();
  const n = lower.length;
  for (let i = 0; i < n; i++) {
    let best = null;
    for (let j = i + 3; j < n; j++) {
      const t = lower.slice(i, j + 1);
      const rev = [...t].reverse().join('');
      if (KEYBOARD_PATTERNS.some((p) => p.includes(t) || p.includes(rev))) best = j;
    }
    if (best !== null) {
      const token = password.slice(i, best + 1);
      matches.push({ type: 'keyboard', i, j: best, token, guessesLog10: log10(100 * token.length) + uppercaseVariations(token) });
    }
  }
  return matches;
}

function dateMatches(password) {
  const matches = [];
  const yearGuesses = (y) => Math.max(Math.abs(y - REFERENCE_YEAR), 20);
  const full = /(\d{1,2})([\/\-. ]?)(\d{1,2})\2(\d{4}|\d{2})/g;
  let m;
  while ((m = full.exec(password)) !== null) {
    const d = +m[1], mo = +m[3];
    let y = +m[4];
    if (m[4].length === 2) y += y > 50 ? 1900 : 2000;
    const valid = (d >= 1 && d <= 31 && mo >= 1 && mo <= 12) || (mo >= 1 && mo <= 31 && d >= 1 && d <= 12);
    if (valid && y >= 1900 && y <= 2099) {
      const g = log10(365 * yearGuesses(y) * (m[2] ? 4 : 1));
      matches.push({ type: 'date', i: m.index, j: m.index + m[0].length - 1, token: m[0], guessesLog10: g });
    }
    full.lastIndex = m.index + 1;
  }
  const yearRe = /(19\d{2}|20\d{2})/g;
  while ((m = yearRe.exec(password)) !== null) {
    matches.push({ type: 'year', i: m.index, j: m.index + 3, token: m[0], guessesLog10: log10(yearGuesses(+m[0])) });
    yearRe.lastIndex = m.index + 1;
  }
  return matches;
}

/**
 * Encontra a decomposição da senha em padrões que minimiza o número de
 * tentativas (programação dinâmica em escala log10).
 */
function minimumGuesses(password, matches) {
  const n = password.length;
  const bf = log10(BRUTEFORCE_CARDINALITY);
  const best = new Array(n + 1).fill(Infinity);
  const back = new Array(n + 1).fill(null);
  best[0] = 0;
  const byEnd = Array.from({ length: n }, () => []);
  for (const m of matches) byEnd[m.j].push(m);
  for (let k = 1; k <= n; k++) {
    // um caractere por força bruta
    if (best[k - 1] + bf < best[k]) { best[k] = best[k - 1] + bf; back[k] = { type: 'bruteforce', i: k - 1, j: k - 1 }; }
    for (const m of byEnd[k - 1]) {
      // pequena penalidade por padrão adicional (o atacante precisa combinar padrões)
      const cost = best[m.i] + m.guessesLog10 + (m.i > 0 ? log10(2) : 0);
      if (cost < best[k]) { best[k] = cost; back[k] = m; }
    }
  }
  const sequence = [];
  let k = n;
  while (k > 0) {
    const m = back[k];
    const last = sequence[0];
    if (m.type === 'bruteforce' && last && last.type === 'bruteforce') {
      last.i = m.i; last.token = password.slice(last.i, last.j + 1);
    } else {
      sequence.unshift({ ...m, token: password.slice(m.i, m.j + 1) });
    }
    k = m.i;
  }
  return { guessesLog10: Math.max(best[n], 0), sequence };
}

function allMatches(password) {
  return [
    ...dictionaryMatches(password), ...sequenceMatches(password), ...repeatMatches(password),
    ...keyboardMatches(password), ...dateMatches(password),
  ];
}

let depth = 0;
/** Estimativa de tentativas (log10) — usada também recursivamente para repetições. */
export function estimateGuessesLog10(password) {
  if (!password) return 0;
  if (depth > 2) return password.length * log10(BRUTEFORCE_CARDINALITY);
  depth++;
  try { return minimumGuesses(password, allMatches(password)).guessesLog10; } finally { depth--; }
}

/** Converte segundos em texto legível em português. */
export function formatDuration(seconds) {
  if (seconds < 1) return 'instantâneo';
  const units = [
    [60, 'segundo', 'segundos'], [60, 'minuto', 'minutos'], [24, 'hora', 'horas'],
    [30.44, 'dia', 'dias'], [12, 'mês', 'meses'], [100, 'ano', 'anos'],
  ];
  let v = seconds;
  for (const [div, sing, plur] of units) {
    if (v < div) { const r = Math.round(v); return `${r} ${r === 1 ? sing : plur}`; }
    v /= div;
  }
  // v em séculos
  if (v < 10000) { const r = Math.round(v); return `${r} ${r === 1 ? 'século' : 'séculos'}`; }
  return 'mais de 1 milhão de anos';
}

function scoreFromGuesses(g) {
  if (g < 3) return 0;
  if (g < 6) return 1;
  if (g < 8) return 2;
  if (g < 10) return 3;
  return 4;
}

const PATTERN_NAMES = {
  dictionary: 'Palavra de dicionário', common: 'Senha comum', sequence: 'Sequência',
  repeat: 'Repetição', keyboard: 'Padrão de teclado', date: 'Data', year: 'Ano', bruteforce: 'Caracteres aleatórios',
};

export function patternName(m) {
  if (m.type === 'dictionary') return m.kind === 'common' ? PATTERN_NAMES.common : PATTERN_NAMES.dictionary;
  return PATTERN_NAMES[m.type];
}

function buildFeedback(password, score, sequence) {
  const suggestions = [];
  let warning = '';
  const patterns = sequence.filter((m) => m.type !== 'bruteforce').sort((a, b) => b.token.length - a.token.length);
  const main = patterns[0];
  if (main) {
    if (main.type === 'dictionary' && main.kind === 'common') {
      warning = main.token.length === password.length
        ? 'Esta é uma das senhas mais usadas — está nas primeiras tentativas de qualquer ataque.'
        : 'A senha contém uma senha muito comum.';
    } else if (main.type === 'dictionary') {
      warning = patterns.length > 1 && patterns.every((p) => p.type === 'dictionary')
        ? '' : 'Palavras isoladas são fáceis de adivinhar com ataques de dicionário.';
    } else if (main.type === 'sequence') warning = 'Sequências como "abc" ou "123" são fáceis de adivinhar.';
    else if (main.type === 'repeat') warning = 'Repetições como "aaa" ou "abcabc" acrescentam pouca segurança.';
    else if (main.type === 'keyboard') warning = 'Padrões de teclado como "qwerty" ou "1qaz" são testados cedo pelos atacantes.';
    else if (main.type === 'date' || main.type === 'year') warning = 'Datas e anos são fáceis de adivinhar, sobretudo se ligados a você.';
    if (patterns.some((p) => p.leet)) suggestions.push('Substituições previsíveis como "@" no lugar de "a" não ajudam muito.');
    if (patterns.some((p) => p.reversed)) suggestions.push('Palavras invertidas não são muito mais difíceis de adivinhar.');
    if (main.type === 'dictionary' && /^[A-Z]/.test(password) && /[\d!@#$%&*]+$/.test(password))
      suggestions.push('Letra maiúscula no início e números no fim são padrões muito previsíveis.');
  }
  if (password.length < 8) suggestions.push('Use pelo menos 8 caracteres; o recomendado são 12 ou mais.');
  else if (password.length < 12 && score < 4) suggestions.push('Aumente o comprimento: cada caractere a mais multiplica o esforço do atacante.');
  if (score < 3) suggestions.push('Experimente uma frase-senha com 4 ou mais palavras aleatórias.');
  if (score >= 3 && !suggestions.length) suggestions.push('Boa senha. Use-a em apenas um serviço e guarde-a em um gerenciador de senhas.');
  return { warning, suggestions: [...new Set(suggestions)] };
}

/**
 * Analisa uma senha e retorna pontuação (0–4), estimativa de tentativas,
 * entropia efetiva, tempos estimados por cenário, padrões e recomendações.
 */
export function analyzePassword(password) {
  if (!password) return null;
  const matches = allMatches(password);
  const { guessesLog10, sequence } = minimumGuesses(password, matches);
  let score = scoreFromGuesses(guessesLog10);
  if (password.length < 8) score = Math.min(score, 1);
  const commonExact = COMMON_RANK.has(password.toLowerCase());
  if (commonExact) score = 0;
  const crackTimes = ATTACK_SCENARIOS.map((s) => {
    const seconds = 10 ** guessesLog10 / s.rate;
    return { ...s, seconds, display: formatDuration(seconds) };
  });
  return {
    password,
    length: password.length,
    score,
    label: SCORE_LABELS[score],
    guessesLog10,
    effectiveBits: guessesLog10 / log10(2),
    bruteForceBits: password.length * Math.log2(charsetSize(password)),
    crackTimes,
    sequence,
    checks: compositionChecks(password),
    feedback: buildFeedback(password, score, sequence),
  };
}
