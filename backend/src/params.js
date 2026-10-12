// Validação de parâmetros numéricos vindos da query/body.
//
// Antes cada rota fazia `parseInt(x) || padrao` por conta própria, e o `||`
// escondia dois bugs reais:
//
//   limit=-1  → "limit $5" com -1 → Postgres: "LIMIT must not be negative"
//               → HTTP 500
//   limit=-1  → lista.slice(0, -1) → devolve tudo MENOS o último item
//   days=abc  → parseInt = NaN → NaN || 0 = 0 → e 0 significa "base
//               inteira", então a tela recebia 3409 IPs e um "todos os dias"
//               que ninguém pediu
//
// Regra daqui: valor ausente/vazio usa o default; valor presente precisa ser
// número de verdade e estar na faixa, senão é 400. Nunca "conserta às cegas".

function numParam(valor, { nome, def, min = 0, max = Number.MAX_SAFE_INTEGER, inteiro = true }) {
  if (valor === undefined || valor === null || valor === '') return def;
  const n = typeof valor === 'number' ? valor : Number(String(valor).trim());
  if (!Number.isFinite(n)) {
    throw Object.assign(new Error(`${nome} inválido: "${valor}" não é número`), { status: 400 });
  }
  if (inteiro && !Number.isInteger(n)) {
    throw Object.assign(new Error(`${nome} inválido: "${valor}" não é inteiro`), { status: 400 });
  }
  if (n < min || n > max) {
    throw Object.assign(new Error(`${nome} fora da faixa (${min}–${max}): "${valor}"`), { status: 400 });
  }
  return n;
}

const intParam = (valor, opts) => numParam(valor, { ...opts, inteiro: true });

// days=0 é legítimo nestas rotas (significa "base inteira", sem filtro de
// janela), por isso o piso é 0 e não 1.
const daysParam = (valor, { def = 0, nome = 'days', max = 365 } = {}) =>
  intParam(valor, { nome, def, min: 0, max });

module.exports = { numParam, intParam, daysParam };