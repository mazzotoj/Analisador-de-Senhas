import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzePassword, formatDuration, charsetSize } from '../src/js/analyzer.js';

test('senha vazia retorna null', () => {
  assert.equal(analyzePassword(''), null);
});

test('senhas comuns recebem pontuação 0', () => {
  for (const p of ['123456', 'senha123', 'P@ssw0rd', 'Senha@123', 'qwerty', 'flamengo']) {
    assert.equal(analyzePassword(p).score, 0, p);
  }
});

test('senhas com menos de 8 caracteres nunca passam de "Fraca"', () => {
  for (const p of ['Ab1!', 'x9#Tq', 'Zk8$pQ2']) assert.ok(analyzePassword(p).score <= 1, p);
});

test('detecta substituições l33t', () => {
  const r = analyzePassword('P@ssw0rd');
  assert.ok(r.sequence.some((m) => m.type === 'dictionary' && m.leet));
});

test('detecta sequências, repetições, teclado e anos', () => {
  const types = (p) => analyzePassword(p).sequence.map((m) => m.type);
  assert.ok(types('xyzabcdefgh').includes('sequence'));
  assert.ok(types('zzzzzzzzzz').includes('repeat'));
  assert.ok(types('asdfghjk!').includes('keyboard'));
  assert.ok(types('Lua#1995').includes('year'));
});

test('frases-senha longas são classificadas como fortes', () => {
  assert.ok(analyzePassword('correcthorsebatterystaple').score >= 3);
  assert.ok(analyzePassword('Tucano-Farol-Pipoca7-Lagoa-Trevo').score === 4);
});

test('senhas aleatórias longas são muito fortes', () => {
  assert.equal(analyzePassword('q8$Lr2!vNz#4Tp9w').score, 4);
});

test('mais comprimento nunca reduz a estimativa de tentativas', () => {
  const a = analyzePassword('gato-lua');
  const b = analyzePassword('gato-lua-ponte-sal');
  assert.ok(b.guessesLog10 > a.guessesLog10);
});

test('feedback em português acompanha a análise', () => {
  const r = analyzePassword('123456');
  assert.match(r.feedback.warning, /senhas mais usadas/);
  assert.ok(r.feedback.suggestions.length > 0);
});

test('quatro cenários de ataque com tempos crescentes para senhas mais fortes', () => {
  const r = analyzePassword('Tucano-Farol-Pipoca7-Lagoa-Trevo');
  assert.equal(r.crackTimes.length, 4);
  assert.ok(r.crackTimes[0].seconds > r.crackTimes[3].seconds);
});

test('formatDuration', () => {
  assert.equal(formatDuration(0.5), 'instantâneo');
  assert.equal(formatDuration(1), '1 segundo');
  assert.equal(formatDuration(120), '2 minutos');
  assert.equal(formatDuration(86400 * 3), '3 dias');
  assert.equal(formatDuration(1e20), 'mais de 1 milhão de anos');
});

test('charsetSize', () => {
  assert.equal(charsetSize('abc'), 26);
  assert.equal(charsetSize('aB1'), 62);
  assert.equal(charsetSize('aB1!'), 95);
});
