# 🔐 Analisador de Senhas

Aplicação web que **avalia a força de senhas por detecção de padrões** e **gera senhas e frases-senha com aleatoriedade criptográfica**. Roda 100% no navegador — nenhuma senha é enviada a servidores.

Projeto Integrador — Análise e Desenvolvimento de Sistemas, Universidade de Vassouras.
Autor: João Victor Mazzoto dos Santos.

## Funcionalidades

**Análise**
- Estimativa do número de tentativas necessárias para adivinhar a senha, com pontuação de 0 a 4 (*Muito fraca* a *Muito forte*).
- Detecção de padrões: senhas comuns, palavras de dicionário (português e inglês), substituições "l33t" (`@`→`a`, `0`→`o`…), palavras invertidas, sequências (`abc`, `123`), repetições (`aaaa`, `abcabc`), padrões de teclado (`qwerty`, `1qaz`), datas e anos.
- Tempo estimado de quebra em quatro cenários de ataque (online com e sem limite, offline com hash lento e rápido).
- Recomendações específicas em português.
- Verificação **opcional** em vazamentos (Have I Been Pwned) com k-anonimato: só os 5 primeiros caracteres do hash SHA-1 são enviados.

**Geração**
- Senhas de 8 a 64 caracteres com escolha de classes, garantia de ao menos um caractere de cada classe e opção de evitar caracteres ambíguos.
- Frases-senha de 3 a 10 palavras em português, com separador, iniciais maiúsculas e número opcionais.
- `crypto.getRandomValues()` com amostragem por rejeição (sem viés de módulo) e embaralhamento Fisher–Yates.
- Exibição da entropia e botão de cópia.

**Interface**
- Campo de senha oculto com botão mostrar/ocultar, medidor visual, tema claro/escuro, layout responsivo e recursos de acessibilidade (rótulos, `aria-live`, navegação por teclado).

## Estrutura

```
├── .github/workflows/deploy.yml   # testes + deploy no GitHub Pages
├── src/                           # site publicado
│   ├── index.html
│   ├── css/style.css
│   ├── assets/favicon.svg
│   └── js/
│       ├── app.js                 # interface (DOM)
│       ├── analyzer.js            # estimador de força
│       ├── generator.js           # gerador de senhas/frases-senha
│       ├── breach.js              # consulta HIBP (k-anonimato)
│       └── data/                  # listas de senhas comuns e palavras
└── tests/                         # testes automatizados (node:test)
```

## Executar localmente

Os scripts usam módulos ES, então é preciso um servidor local (abrir o `index.html` direto pelo arquivo não funciona):

```bash
cd src
python3 -m http.server 8000
# acesse http://localhost:8000
```

## Testes

Requer Node.js 20 ou superior, sem dependências externas:

```bash
npm test
```

## Publicação no GitHub Pages

1. Envie o projeto para a branch `main`.
2. No repositório, vá em **Settings → Pages** e, em **Source**, selecione **GitHub Actions**.
3. A cada push, o workflow roda os testes e, se passarem, publica a pasta `src/`.
   O endereço fica disponível em `https://<usuario>.github.io/Analisador-de-Senhas/`.

## Referências

- GRASSI, P. A. *et al.* NIST SP 800-63B — Digital Identity Guidelines, 2017.
- WHEELER, D. L. zxcvbn: low-budget password strength estimation. USENIX Security, 2016.
- OWASP Authentication Cheat Sheet.
- Have I Been Pwned — Pwned Passwords API.

## Licença

MIT
