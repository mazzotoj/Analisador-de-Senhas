/**
 * app.js — Liga a interface (DOM) aos módulos de análise, geração e
 * verificação de vazamentos.
 */
import { analyzePassword, patternName } from './analyzer.js';
import {
  generatePassword, generatePassphrase, passwordEntropy, passphraseEntropy, WORDLIST_SIZE,
} from './generator.js';
import { checkBreach } from './breach.js';

const $ = (id) => document.getElementById(id);

const el = {
  senha: $('senha'), toggle: $('toggle-visibilidade'), medidor: $('medidor'), forca: $('forca-texto'),
  resultado: $('resultado'), tentativas: $('stat-tentativas'), entropia: $('stat-entropia'),
  comprimento: $('stat-comprimento'), feedback: $('feedback'), tempos: $('tempos'), padroes: $('padroes'),
  composicao: $('composicao'), vazamento: $('verificar-vazamento'), vazamentoStatus: $('vazamento-status'),
  gerada: $('gerada'), copiar: $('copiar'), regenerar: $('regenerar'), entropiaGerada: $('entropia-gerada'),
  entropiaNivel: $('entropia-nivel'), analisarGerada: $('analisar-gerada'), toast: $('toast'),
  tabSenha: $('tab-senha'), tabFrase: $('tab-frase'), painelSenha: $('painel-senha'), painelFrase: $('painel-frase'),
  comprimentoRange: $('comprimento'), comprimentoValor: $('comprimento-valor'),
  palavras: $('palavras'), palavrasValor: $('palavras-valor'), separador: $('separador'),
  opMin: $('op-minusculas'), opMai: $('op-maiusculas'), opNum: $('op-numeros'), opSim: $('op-simbolos'),
  opAmb: $('op-ambiguos'), opCap: $('op-capitalizar'), opNumero: $('op-numero'), infoLista: $('info-lista'),
};

/* ---------------------- utilidades ---------------------- */
function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function formatGuesses(log10) {
  if (log10 < 6) return Math.max(1, Math.round(10 ** log10)).toLocaleString('pt-BR');
  return `10^${log10.toFixed(1).replace('.', ',')}`;
}

let toastTimer;
function toast(msg) {
  el.toast.textContent = msg;
  el.toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.toast.classList.remove('show'), 1800);
}

function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

/* ---------------------- análise ---------------------- */
const CHECK_LABELS = {
  minLength: 'Mínimo de 8 caracteres', recommendedLength: '12 ou mais caracteres',
  lower: 'Letras minúsculas', upper: 'Letras maiúsculas', digit: 'Números', symbol: 'Símbolos',
};

function render(result) {
  if (!result) {
    el.medidor.removeAttribute('data-score');
    el.medidor.setAttribute('aria-valuenow', '0');
    el.forca.removeAttribute('data-score');
    el.forca.textContent = 'Digite uma senha para começar.';
    el.resultado.hidden = true;
    return;
  }
  const { score } = result;
  el.medidor.dataset.score = score;
  el.medidor.setAttribute('aria-valuenow', String(score));
  el.medidor.setAttribute('aria-valuetext', result.label);
  el.forca.dataset.score = score;
  el.forca.textContent = `Força: ${result.label}`;
  el.resultado.hidden = false;

  el.tentativas.textContent = formatGuesses(result.guessesLog10);
  el.entropia.textContent = `${Math.round(result.effectiveBits)} bits`;
  el.comprimento.textContent = `${result.length} caracteres`;

  const { warning, suggestions } = result.feedback;
  el.feedback.innerHTML =
    (warning ? `<p class="warning">${escapeHtml(warning)}</p>` : '') +
    (suggestions.length ? `<ul>${suggestions.map((s) => `<li>${escapeHtml(s)}</li>`).join('')}</ul>` : '');

  el.tempos.innerHTML = result.crackTimes
    .map((c) => `<tr><td>${escapeHtml(c.label)}<small>${c.rate >= 1 ? c.rate.toLocaleString('pt-BR') + ' tentativas/s' : '100 tentativas/hora'}</small></td><td>${escapeHtml(c.display)}</td></tr>`)
    .join('');

  el.padroes.innerHTML = result.sequence
    .map((m) => {
      let extra = '';
      if (m.leet) extra = ' (com substituições)';
      else if (m.reversed) extra = ' (invertida)';
      return `<li>${escapeHtml(patternName(m))}${extra}: <code>${escapeHtml(m.token)}</code></li>`;
    })
    .join('');

  el.composicao.innerHTML = Object.entries(result.checks)
    .map(([k, ok]) => `<li class="${ok ? 'ok' : ''}">${CHECK_LABELS[k]}</li>`)
    .join('');
}

let breachSeq = 0;
const runBreachCheck = debounce(async (password) => {
  const seq = ++breachSeq;
  if (!el.vazamento.checked || !password) { el.vazamentoStatus.textContent = ''; return; }
  el.vazamentoStatus.className = 'breach__status';
  el.vazamentoStatus.textContent = 'Consultando…';
  try {
    const { count } = await checkBreach(password);
    if (seq !== breachSeq) return; // resposta de uma digitação anterior
    if (count > 0) {
      el.vazamentoStatus.className = 'breach__status bad';
      el.vazamentoStatus.textContent = `Atenção: esta senha apareceu ${count.toLocaleString('pt-BR')} vez(es) em vazamentos. Não a utilize.`;
    } else {
      el.vazamentoStatus.className = 'breach__status ok';
      el.vazamentoStatus.textContent = 'Não encontrada em vazamentos conhecidos.';
    }
  } catch {
    if (seq !== breachSeq) return;
    el.vazamentoStatus.className = 'breach__status';
    el.vazamentoStatus.textContent = 'Não foi possível consultar agora (verifique sua conexão).';
  }
}, 600);

function onPasswordInput() {
  const pw = el.senha.value;
  render(analyzePassword(pw));
  runBreachCheck(pw);
}

el.senha.addEventListener('input', onPasswordInput);
el.vazamento.addEventListener('change', () => runBreachCheck(el.senha.value));
el.toggle.addEventListener('click', () => {
  const show = el.senha.type === 'password';
  el.senha.type = show ? 'text' : 'password';
  el.toggle.setAttribute('aria-pressed', String(show));
  el.toggle.setAttribute('aria-label', show ? 'Ocultar senha' : 'Mostrar senha');
});

/* ---------------------- gerador ---------------------- */
let mode = 'senha';

function passwordOptions() {
  return {
    length: +el.comprimentoRange.value, lower: el.opMin.checked, upper: el.opMai.checked,
    digits: el.opNum.checked, symbols: el.opSim.checked, excludeAmbiguous: el.opAmb.checked,
  };
}
function passphraseOptions() {
  return { words: +el.palavras.value, separator: el.separador.value, capitalize: el.opCap.checked, addNumber: el.opNumero.checked };
}

function entropyLevel(bits) {
  if (bits < 50) return ['Baixa', 'var(--s1)'];
  if (bits < 70) return ['Boa', 'var(--s3)'];
  return ['Excelente', 'var(--s4)'];
}

function generate() {
  let value, bits;
  try {
    if (mode === 'senha') {
      const o = passwordOptions();
      value = generatePassword(o);
      bits = passwordEntropy(o);
    } else {
      const o = passphraseOptions();
      value = generatePassphrase(o);
      bits = passphraseEntropy(o);
    }
  } catch (e) {
    el.gerada.value = '';
    el.entropiaGerada.textContent = '–';
    el.entropiaNivel.textContent = '';
    toast(e.message);
    return;
  }
  el.gerada.value = value;
  el.entropiaGerada.textContent = `${Math.round(bits)} bits`;
  const [lvl, color] = entropyLevel(bits);
  el.entropiaNivel.textContent = lvl;
  el.entropiaNivel.style.background = color;
}

function selectTab(tab) {
  mode = tab === el.tabSenha ? 'senha' : 'frase';
  for (const t of [el.tabSenha, el.tabFrase]) {
    const sel = t === tab;
    t.setAttribute('aria-selected', String(sel));
    t.tabIndex = sel ? 0 : -1;
  }
  el.painelSenha.hidden = mode !== 'senha';
  el.painelFrase.hidden = mode !== 'frase';
  generate();
}

el.tabSenha.addEventListener('click', () => selectTab(el.tabSenha));
el.tabFrase.addEventListener('click', () => selectTab(el.tabFrase));
for (const t of [el.tabSenha, el.tabFrase]) {
  t.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      const other = t === el.tabSenha ? el.tabFrase : el.tabSenha;
      selectTab(other);
      other.focus();
    }
  });
}

el.comprimentoRange.addEventListener('input', () => { el.comprimentoValor.textContent = el.comprimentoRange.value; generate(); });
el.palavras.addEventListener('input', () => { el.palavrasValor.textContent = el.palavras.value; generate(); });
for (const c of [el.opMin, el.opMai, el.opNum, el.opSim, el.opAmb, el.opCap, el.opNumero, el.separador]) {
  c.addEventListener('change', generate);
}
el.regenerar.addEventListener('click', generate);

el.copiar.addEventListener('click', async () => {
  if (!el.gerada.value) return;
  try {
    await navigator.clipboard.writeText(el.gerada.value);
  } catch {
    el.gerada.select();
    document.execCommand('copy');
  }
  toast('Senha copiada!');
});

el.analisarGerada.addEventListener('click', () => {
  el.senha.value = el.gerada.value;
  onPasswordInput();
  el.senha.focus();
  el.senha.scrollIntoView({ behavior: 'smooth', block: 'center' });
});

/* ---------------------- tema ---------------------- */
$('theme-toggle').addEventListener('click', () => {
  const root = document.documentElement;
  const current = root.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  const next = current === 'dark' ? 'light' : 'dark';
  root.dataset.theme = next;
  try { localStorage.setItem('tema', next); } catch { /* armazenamento indisponível */ }
});

/* ---------------------- início ---------------------- */
el.infoLista.textContent = `Palavras sorteadas de uma lista de ${WORDLIST_SIZE} termos em português (≈${Math.log2(WORDLIST_SIZE).toFixed(1).replace('.', ',')} bits por palavra).`;
generate();
