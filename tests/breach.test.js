import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sha1Hex, findSuffixCount, checkBreach } from '../src/js/breach.js';

test('SHA-1 calculado localmente', async () => {
  assert.equal(await sha1Hex('password'), '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
});

test('apenas o prefixo de 5 caracteres é enviado (k-anonimato)', async () => {
  let url = '';
  const fakeFetch = async (u) => {
    url = u;
    return { ok: true, text: async () => '1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n0000000000000000000000000000000000:0' };
  };
  const r = await checkBreach('password', fakeFetch);
  assert.equal(url, 'https://api.pwnedpasswords.com/range/5BAA6');
  assert.equal(r.count, 3861493);
});

test('senha ausente retorna 0', () => {
  assert.equal(findSuffixCount('AAAA:1\nBBBB:2', 'CCCC'), 0);
});
