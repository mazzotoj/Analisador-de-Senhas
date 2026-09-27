/**
 * breach.js — Verificação opcional em bases de senhas vazadas
 * (Have I Been Pwned — Pwned Passwords) usando k-anonimato.
 *
 * A senha NUNCA é enviada: calcula-se o SHA-1 localmente e apenas os
 * 5 primeiros caracteres do hash são consultados. A comparação do restante
 * acontece no navegador. O cabeçalho Add-Padding dificulta a análise de
 * tráfego pelo tamanho da resposta.
 */
const API = 'https://api.pwnedpasswords.com/range/';

export async function sha1Hex(text) {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-1', data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/** Procura o sufixo do hash na resposta da API e devolve a contagem. */
export function findSuffixCount(responseText, suffix) {
  for (const line of responseText.split('\n')) {
    const [s, count] = line.trim().split(':');
    if (s === suffix) return parseInt(count, 10) || 0;
  }
  return 0;
}

/**
 * Retorna quantas vezes a senha aparece em vazamentos conhecidos.
 * @param {string} password
 * @param {typeof fetch} fetchImpl  permite injetar um fetch simulado nos testes
 */
export async function checkBreach(password, fetchImpl = globalThis.fetch) {
  const hash = await sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const res = await fetchImpl(API + prefix, { headers: { 'Add-Padding': 'true' } });
  if (!res.ok) throw new Error(`Falha na consulta (${res.status})`);
  return { count: findSuffixCount(await res.text(), suffix), prefix };
}
