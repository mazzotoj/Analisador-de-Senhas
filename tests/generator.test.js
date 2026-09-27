import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  randomInt, shuffle, generatePassword, generatePassphrase, passwordEntropy, passphraseEntropy,
  CHARSETS, AMBIGUOUS, WORDLIST_SIZE,
} from '../src/js/generator.js';

test('randomInt fica no intervalo e rejeita entradas inválidas', () => {
  for (let i = 0; i < 1000; i++) {
    const x = randomInt(7);
    assert.ok(x >= 0 && x < 7 && Number.isInteger(x));
  }
  assert.throws(() => randomInt(0));
  assert.throws(() => randomInt(1.5));
});

test('randomInt é aproximadamente uniforme (qui-quadrado)', () => {
  const k = 10, n = 50000, counts = new Array(k).fill(0);
  for (let i = 0; i < n; i++) counts[randomInt(k)]++;
  const e = n / k;
  const chi2 = counts.reduce((s, c) => s + (c - e) ** 2 / e, 0);
  assert.ok(chi2 < 27.88, `qui-quadrado = ${chi2}`); // p = 0,001 com 9 g.l.
});

test('shuffle preserva os elementos', () => {
  const a = [1, 2, 3, 4, 5, 6];
  assert.deepEqual([...shuffle(a)].sort(), a);
});

test('senha gerada respeita o comprimento e contém todas as classes', () => {
  for (let i = 0; i < 500; i++) {
    const p = generatePassword({ length: 12 });
    assert.equal(p.length, 12);
    assert.match(p, /[a-z]/); assert.match(p, /[A-Z]/); assert.match(p, /[0-9]/); assert.match(p, /[^A-Za-z0-9]/);
  }
});

test('respeita as classes selecionadas e a exclusão de ambíguos', () => {
  for (let i = 0; i < 200; i++) {
    const p = generatePassword({ length: 20, symbols: false, upper: false, excludeAmbiguous: true });
    assert.match(p, /^[a-z0-9]+$/);
    for (const c of AMBIGUOUS) assert.ok(!p.includes(c));
  }
});

test('erro quando nenhuma classe é selecionada', () => {
  assert.throws(() => generatePassword({ lower: false, upper: false, digits: false, symbols: false }));
});

test('entropia da senha padrão (16 caracteres, 87 símbolos)', () => {
  const pool = Object.values(CHARSETS).join('').length;
  assert.equal(pool, 87);
  assert.ok(Math.abs(passwordEntropy() - 16 * Math.log2(87)) < 1e-9);
});

test('frase-senha tem o número de palavras pedido', () => {
  const p = generatePassphrase({ words: 6, separator: '-', addNumber: false });
  assert.equal(p.split('-').length, 6);
  assert.ok(passphraseEntropy({ words: 6, addNumber: false }) > 6 * 9);
  assert.ok(WORDLIST_SIZE >= 700);
});

test('100 senhas geradas são todas distintas', () => {
  const set = new Set(Array.from({ length: 100 }, () => generatePassword()));
  assert.equal(set.size, 100);
});
