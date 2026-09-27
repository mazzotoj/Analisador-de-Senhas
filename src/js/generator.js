/**
 * generator.js — Geração de senhas e frases-senha com aleatoriedade
 * criptograficamente segura (Web Crypto API: crypto.getRandomValues).
 */
import { WORDLIST_PT } from './data/wordlist-pt.js';

export const CHARSETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?/~',
};
/** Caracteres facilmente confundidos visualmente. */
export const AMBIGUOUS = 'Il1O0o|`\'"';

/**
 * Inteiro aleatório uniforme em [0, max) usando amostragem por rejeição,
 * o que elimina o viés do operador módulo.
 */
export function randomInt(max) {
  if (!Number.isInteger(max) || max <= 0 || max > 2 ** 32) throw new RangeError('max inválido');
  const limit = Math.floor(2 ** 32 / max) * max;
  const buf = new Uint32Array(1);
  let x;
  do { crypto.getRandomValues(buf); x = buf[0]; } while (x >= limit);
  return x % max;
}

/** Embaralhamento de Fisher–Yates com fonte criptográfica. */
export function shuffle(array) {
  const a = [...array];
  for (let i = a.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function buildPools({ lower, upper, digits, symbols, excludeAmbiguous }) {
  const pools = [];
  const clean = (s) => (excludeAmbiguous ? [...s].filter((c) => !AMBIGUOUS.includes(c)).join('') : s);
  if (lower) pools.push(clean(CHARSETS.lower));
  if (upper) pools.push(clean(CHARSETS.upper));
  if (digits) pools.push(clean(CHARSETS.digits));
  if (symbols) pools.push(clean(CHARSETS.symbols));
  return pools;
}

export const DEFAULT_PASSWORD_OPTIONS = Object.freeze({
  length: 16, lower: true, upper: true, digits: true, symbols: true, excludeAmbiguous: false,
});

/**
 * Gera uma senha aleatória garantindo ao menos um caractere de cada
 * classe selecionada.
 */
export function generatePassword(options = {}) {
  const opts = { ...DEFAULT_PASSWORD_OPTIONS, ...options };
  const pools = buildPools(opts);
  if (!pools.length) throw new Error('Selecione ao menos um tipo de caractere.');
  const length = Math.max(Math.min(Math.floor(opts.length), 128), pools.length, 4);
  const all = pools.join('');
  const chars = pools.map((p) => p[randomInt(p.length)]);
  while (chars.length < length) chars.push(all[randomInt(all.length)]);
  return shuffle(chars).join('');
}

/** Entropia (bits) de uma senha gerada com as opções informadas. */
export function passwordEntropy(options = {}) {
  const opts = { ...DEFAULT_PASSWORD_OPTIONS, ...options };
  const pool = buildPools(opts).join('').length;
  return pool ? opts.length * Math.log2(pool) : 0;
}

export const DEFAULT_PASSPHRASE_OPTIONS = Object.freeze({
  words: 5, separator: '-', capitalize: true, addNumber: true,
});

/** Gera uma frase-senha com palavras sorteadas da lista em português. */
export function generatePassphrase(options = {}) {
  const opts = { ...DEFAULT_PASSPHRASE_OPTIONS, ...options };
  const count = Math.max(3, Math.min(Math.floor(opts.words), 12));
  const words = Array.from({ length: count }, () => {
    const w = WORDLIST_PT[randomInt(WORDLIST_PT.length)];
    return opts.capitalize ? w[0].toUpperCase() + w.slice(1) : w;
  });
  if (opts.addNumber) {
    const idx = randomInt(words.length);
    words[idx] += String(randomInt(10));
  }
  return words.join(opts.separator);
}

/** Entropia (bits) de uma frase-senha gerada com as opções informadas. */
export function passphraseEntropy(options = {}) {
  const opts = { ...DEFAULT_PASSPHRASE_OPTIONS, ...options };
  let bits = opts.words * Math.log2(WORDLIST_PT.length);
  if (opts.addNumber) bits += Math.log2(10 * opts.words);
  return bits;
}

export const WORDLIST_SIZE = WORDLIST_PT.length;
