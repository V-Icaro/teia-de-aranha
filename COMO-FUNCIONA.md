# 🕸️ Teia de Aranha — Como tudo funciona

Documento completo das funcionalidades e suas lógicas. Nada resumido: limiares,
fórmulas, decisões de projeto e limitações conhecidas.

---

## 1. Visão geral

```
VMware (vSwitch/vDS com NetFlow/IPFIX)
   │ exporta fluxos
   ▼
Elasticsearch (índice netflow-*, https://172.20.20.250:9200)
   │ consulta via agregações
   ▼
Backend Node + Express (:3001) ── transforma em grafo + analisa + enriquece
   │ REST /api/*
   ▼
Frontend React + Vite + Cytoscape.js (:5173)
```

**Ponto fundamental:** o mapa mostra **apenas o que o exportador NetFlow do
VMware enxerga**. Tráfego que não cruza o switch monitorado (ex.: seu PC →
Elasticsearch direto na 9200) é invisível nos fluxos. Isso não é bug — foi
comprovado comparando contagens diretas no índice.

---

## 2. Backend (`backend/`)

### 2.1. Conexão com o Elasticsearch (`src/elastic.js`)

- Cliente `@elastic/elasticsearch` v8 apontando para `ELASTIC_URL`.
- Auth: `ELASTIC_API_KEY` preferida, senão `ELASTIC_USER` + `ELASTIC_PASS`.
- **TLS self-signed:** por padrão `rejectUnauthorized: false` (lab), com aviso
  no log. Para produção: `ELASTIC_TLS_REJECT_UNAUTHORIZED=1` + `ELASTIC_CA_FINGERPRINT`
  ou `ELASTIC_CA_FILE`.
- `sniffOnStart: false` — o sniffing tentava descobrir nós com certificado
  inválido e quebrava tudo (foi o primeiro erro que apareceu).
- Timeout de requisição 30s, 2 tentativas.

### 2.2. Campos do índice (mapeamento real verificado)

| Campo | Tipo | Uso |
|---|---|---|
| `netflow.sourceIPv4Address` / `destinationIPv4Address` | `text` + sub-campo `.keyword` | origem/destino — agregação usa o **`.keyword`** (o `text` puro dá erro `fielddata disabled`) |
| `netflow.protocolIdentifier` | `long` | 6=TCP, 17=UDP, 1=ICMP… (tabela `PROTOCOLS` traduz número→nome) |
| `netflow.sourceTransportPort` / `destinationTransportPort` | `long` | portas; origem é efêmera (aleatória por conexão) |
| `netflow.octetDeltaCount` / `packetDeltaCount` | `long` | somados (`sum`) = bytes/pacotes do fluxo |
| `netflow.flowEndMilliseconds` (`date`), `flowEndReason` | data/long | filtro de **conexões ativas** |
| `@timestamp` | `date` | filtro de janela |

O índice **não tem** camada 7: sem SNI, sem hostname, sem DNS. Por isso o "nome
do site" (ex. youtube.com) nunca vem do fluxo — só de enriquecimento externo
(§2.5). Campos `vmware*` e `flowDirection` existem mas não são usados.

### 2.3. Consulta principal — `fetchConnections()` (`src/elastic.js`)

Agregação `composite` (a que você passou, estendida):

- `sources`: origem + destino + protocolo + porta_destino.
- **Porta de origem de fora por padrão:** incluí-la multiplicava os buckets
  10–50x (cada conexão tem sport única) e o teto cortava pares inteiros do
  mapa — foi assim que seu SSH sumiu uma vez (janela estourou 20.000 buckets).
  Quem precisa dela (detalhe do host) usa `withSport: true` + filtro de IP
  (volume pequeno, sem explosão).
- Sub-agregações: `bytes = sum(octetDeltaCount)`, `pacotes = sum(packetDeltaCount)`.
- Filtro de tempo: `?minutes=N` (vira `now-Nm`), `?range=` cru ou
  `?from=ISO&to=ISO`.
- Filtro opcional de IP (`term` em origem **ou** destino) — usado pelo detalhe
  do host, comparador e dossiê.
- Filtro opcional de ativas (`activeSec`): `flowEndMilliseconds >= now-Ns`.
  "Ativa" = teve pacote nos últimos N segundos (padrão 120s). Cobre sessão
  aberta (o exporter reexporta por *active timeout*) e recém-encerrada.
- **Sem teto:** pagina `after_key` até esgotar (`MAX_EDGES` só como trava
  opcional de emergência; padrão `Infinity`). Retorna `truncated: true` se
  algum teto cortar.

### 2.4. Grafo — `toCytoscape()` (`src/elastic.js`)

Agrega buckets por **par (origem, destino, protocolo)** — 1 aresta por par:

- `bytes`/`packets` somados (espessura da linha reflete tudo), `flows` = nº de
  fluxos, ranking de portas destino (top 15 com bytes), amostra de até 50
  portas de origem.
- **Portas de serviço primeiro:** serviço = ≤1023 ou lista `KNOWN_SERVICE_PORTS`
  (1433, 3306, 3389, 5432, 9200, 10051, 1514, 2055…). Rótulo = porta de serviço
  + nº de fluxos (`1514 · 3 fluxos`); direção só com efêmeras vira
  `retorno · N fluxos`. Efêmeras nunca são apagadas — ficam nos detalhes.
- Nós: um por IP (`{ id, label }`); `subnet` (/24 v4, /64 v6) anexada depois.
- Auto-loops (origem = destino) descartados.

Exemplo real: 60 min foram de **4618 arestas → 51** sem perder informação.

### 2.5. Nomes (`src/names.js`) — ordem de prioridade

1. **Inventário PostgreSQL** — nome da máquina por IP cadastrado; é a fonte
   prioritária e pode associar várias interfaces/IPs e aplicações/listeners.
2. **Inventário estático legado** (`INVENTORY_FILE`, JSON `{ip: nome}`).
3. **rDNS** (`dns.reverse`, timeout 1,5s, cache 1h, concorrência 20, teto 2000
   IPs). Cobre internos com PTR (ex. `SRV-AD.aspectu.local`) e públicos
   (ex. `dns.google`, `*.googlevideo.com` — o fingerprint do YouTube).
4. **ASN/organização via Team Cymru** (DNS, sem chave, cache 24h): ex.
   `AS15169 GOOGLE`. Privados pulam.
5. **Domínio do AbuseIPDB** (quando a reputação é consultada e não há PTR).

Sem PTR, o nome vem do inventário cadastrado; sem inventário, não há mágica:
18/28 internos não resolviam na rede original.

`RDNS_DNS_SERVERS` permite forçar DNS externo (8.8.8.8) se o interno não
resolve a internet. **Cuidado:** DNS público quebra DNSBL/Spamhaus (não mais
usados aqui, mas vale o registro).

### 2.6. Reputação (`src/reputation.js`) — só AbuseIPDB, binária

- `POST /api/reputation {ips}` (teto 100/chamada, concorrência 6, cache 6h,
  timeout 8s).
- `POST /api/reputation/coverage {ips}` — **não chama o AbuseIPDB**: diz o que já
  está em memória (6h) ou no Postgres (`REP_PG_TTL_DAYS`, padrão 7 dias), com a
  idade de cada veredito, além do estado da cota. É o que permite pintar a lista
  de reputação sem gastar nada e o botão só ir atrás do que falta.
- Veredito: **score 0 = confiável (verde)** | **score > 0 = não confiável
  (vermelho)**. Sem chave ou API fora = cinza (não verificado); interno = cinza
  (rede interna). Decisão consciente: score 0 com reportes (ex. 8.8.8.8 com 208)
  é ruído de infra pública — o número de reportes aparece na UI sem subir o
  veredito.
- Retorna também país, ISP, domínio, hostnames, uso, whitelist (tudo que a API
  verbose entrega) — alimenta o dossiê e o nome reserva.
- Histórico: ThreatFox (passou a exigir chave, removido) e DNSBLs (Spamhaus não
  respondia no seu DNS; SpamCop/PSBL funcionavam) foram descartados a seu
  pedido. O código tem autoteste de zona documentado caso um dia volte.
- `GET /api/reputation/overview?days=N` — agregado do painel (KPIs, faixas de
  score, contexto de uso, países, ISPs, série diária e notas de retenção).
  Consulta **só Postgres + `pair_daily`**, exceto os bytes de 24h, que vêm do ES
  porque o `pair_daily` não tem dia corrente. Score aplicado é o de hoje; o corte
  de contexto usa `usage_type` (`Data Center/Hosting/Transit/Content Delivery` →
  hospedagem, `ISP` → operadora, `University/Education/Government/Commercial/
  Corporate` → institucional).

### 2.7. Top talkers (`src/detect.js`, via `GET /api/alerts`)

Top N (`ALERT_TOP_N`, padrão 10) IPs por bytes totais (entrada + saída) na
janela, com in/out separados e nº de peers. É ranking, não alerta.

### 2.8. Endpoints

| Método e rota | Parâmetros | Retorna |
|---|---|---|
| `GET /api/health` | — | `{ ok, elastic, ping }` |
| `GET /api/graph` | `minutes` \| `range` \| `from`+`to`; `names=1` (enriquece) | `{ nodes, edges, meta { truncated, … } }` |
| `GET /api/host/:ip` | mesmos de tempo + `active=1` | totais in/out, top 100 peers (portas serviço-primeiro, protocolos traduzidos) |
| `GET /api/alerts` | tempo | `topTalkers, meta{window}` |
| `POST /api/resolve` | `{ ips[] }` | `{ names, info{asn,org,prefix}, subnets }` |
| `POST /api/reputation` | `{ ips[] }` (máx 100) | `{ rep: { ip: { verdict, sources, abuse } } }` |
| `POST /api/reputation/coverage` | `{ ips[] }` (máx 300) | o que já está em cache + idade + estado da cota, **sem** chamar o AbuseIPDB |
| `GET /api/reputation/db` | `days=0` (base toda) `order=rep\|reports\|bytes\|seen` | **base de reputação**: todos os IPs já verificados (`ip_reputation`) + histórico de conexões (`ip_sightings`), agrupados por país e ordenados por score |
| `GET /api/reputation/overview` | `days=1\|7\|30\|0` | **painel de reputação**: KPIs, faixas de score, contexto de uso, países, ISPs, série diária e notas de retenção/fonte |
| `GET /api/ip/:ip` | tempo | **dossiê**: identidade + reputação + tráfego (top peers/portas, fluxos) |
| `GET /api/compare?a=&b=` | tempo | A→B e B→A (bytes/fluxos), timeline (1/5/15 min auto), top portas por direção |
| `GET /api/top-pairs` | tempo + `subnet?` | top 10 pares bidirecionais |
| `GET /api/lookup?ip=&days=` | 7/14/30 | primeira/última vez, peers, portas, atividade diária |
| `POST /api/stats/harvest` | `{hours}` | coleta manual do histórico (botão "⇅ coletar base" na tela de reputação) |
| `GET /api/risk` | tempo + `only=all\|withbad\|clean` `limit` | **exposição a IP malicioso por host**: bytes que foram para score>0, ponderados pelo score |
| `GET /api/inbound` | tempo + `limit` | fluxos IPv4 público→privado, incluindo protocolos sem porta |
| `GET /api/new-external` | tempo + `onlyNew=1` `limit` | IPs de destino globalmente novos ou ausentes no snapshot diário; ausências são candidatos, não confirmação |
| `GET /api/sessions` | tempo + `activeSec` (padrão 120) | pares com fluxo vivo: duração, bps, portas de serviço |
| `GET /api/beacon` | `src` `dst` `minutes` | periodicidade do par: intervalo médio, desvio, cv, `periodic` |
| `/api/inventory` | GET/POST; servidores, IPs, aplicações e listeners | inventário persistido no Postgres |
| `/api/inventory/servers/:id` | PATCH/DELETE; `POST /ips`, `POST /applications` | gestão de máquinas e seus endereços/aplicações |
| `/api/inventory/applications/:id` | PATCH/DELETE; `POST /listeners` | gestão de aplicações e listeners `IP + TCP/UDP + porta` |
| `GET/POST /api/subnets` · `PATCH/DELETE /api/subnets/:cidr` | `{cidr, name, is_default?}` | sub-redes monitoradas: filtro do mapa e "abre junto com o sistema" |

> A feature de **vigilância de hosts** (vigiados, achados, suspeitos, allowlist e cron
> próprio) foi removida. As tabelas `watched_hosts`, `findings`, `known_peers` e
> `pair_allowlist` continuam no banco, órfãs — nada as cria, lê ou escreve.

### 2.10. Variáveis de ambiente (todas)

Elastic/TLS: `ELASTIC_URL`, `ELASTIC_USER`, `ELASTIC_PASS`, `ELASTIC_API_KEY`,
`ELASTIC_INDEX`, `ELASTIC_TLS_REJECT_UNAUTHORIZED`, `ELASTIC_CA_FINGERPRINT`,
`ELASTIC_CA_FILE`. Campos: `ELASTIC_FIELD_{SRC,DST,PROTO,SPORT,DPORT}`.
Grafo: `PORT`, `MAX_EDGES` (trava opcional), `COMPOSITE_PAGE_SIZE`,
`KNOWN_SERVICE_PORTS`. Nomes: `RDNS_ENABLED`, `RDNS_TIMEOUT_MS`,
`RDNS_CACHE_TTL_MS`, `RDNS_DNS_SERVERS`, `ASN_ENABLED`, `ASN_CACHE_TTL_MS`,
`INVENTORY_FILE`. Top talkers: `ALERT_TOP_N`. Conexões ativas:
`ACTIVE_WINDOW_SEC`. Reputação: `ABUSEIPDB_KEY`, `REP_CACHE_TTL_MS`,
`REP_TIMEOUT_MS`, `REP_PG_TTL_DAYS`. Série diária: `DAILY_CRON` (padrão `40 6 * * *`,
0 = desliga), `DAILY_MAX_DAYS`. Postgres: `PGHOST/PORT/USER/PASSWORD/DATABASE`
ou `DATABASE_URL` (sub-redes, histórico de IPs, série diária, reputação).
Fuso dos crons: `CRON_TZ`. Coleta de IPs públicos: `REGIONS_CRON`.
Fuso dos "dias" dos relatórios: `REPORT_TZ` (padrão `America/Fortaleza`, ver 3.6b).

---

## 3. Frontend (`frontend/` — React + Vite + Cytoscape.js)

Proxy do Vite: `/api` → `localhost:3001` (só em `dev`).

### 3.1. Mapa

- **Nós** = hosts. Interno = círculo ciano `#22d3ee`; **IP público = círculo, e a
  cor dele é a reputação** (vermelho `#ef4444` malicioso, verde `#22c55e` limpo,
  cinza `#94a3b8` não verificado); sub-rede = hexágono violeta `#7c3aed`.
  **Arestas** = pares + protocolo (cor por protocolo, seta de direção).
  A cor por /24 foi descartada: era ruído (cada host da internet virava uma
  matiz). Público não usa borda — a reputação já está no preenchimento.
  (O Cytoscape não tem shape de nuvem: se um dia quiser, é `background-image`
  com SVG + `background-color: transparent`, senão o círculo aparece atrás.)
  Nunca use `hsl()` para cor no Cytoscape: ele não aceita espaço e o estilo
  inteiro é descartado (`background-color ... is invalid`). Converta para hex.
- **Espessura** = bytes em escala log (`0,6 + t·2,4`, 0,6–3px) — outliers não
  explodem o desenho.
- **Rótulo** = porta de serviço + nº de fluxos (`1514 · 3 fluxos`); só efêmeras
  = `retorno · N fluxos` (desligável).
- **Estabilidade (importante):** dois efeitos separados — mudança **estrutural**
  (dados, filtros, visão) reconstrói voltando às posições salvas (sem
  randomizar); mudança **cosmética** (nomes chegando, rótulos) só reavalia
  estilos, sem tocar no grafo. Só **Reorganizar** reanima tudo de propósito.
  (Antes, cada nome resolvido reanimava o mapa inteiro.)
- **Modo desempenho** automático acima de 1200 elementos: sem animação, menos
  iterações, textura no viewport (chip "modo desempenho" avisa).
- **Visões:** Hosts ⇄ Sub-redes /24 (hexágonos agregados com bytes/fluxos);
  clique na sub-rede = drill-down (só ela + vizinhos, com "ver tudo").
- **Filtros:** período 5M–24H ou personalizado, protocolo, bytes mínimos,
  busca de IP (Enter localiza), layout (força/concêntrico/círculo/grade),
  distância 120–1000px, mostrar portas, mostrar nomes (padrão ligado),
  sub-rede monitorada (com default ★ na abertura).

### 3.2. Painéis

- **Host:** totais in/out, pacotes, tabela de peers (seta de direção, IP +
  bolinha de reputação clicável, bytes, ESTADO 🟢/⚪ com desde/quando,
  protocolo traduzido) com sub-linhas HOST→PEER / PEER→HOST (top 5 pares
  `origem→destino`).
- **Aresta:** bytes, pacotes, fluxos, protocolo, ranking de portas destino com
  volume, amostra de origens.
- **Modal de IP público:** dossiê completo (identidade, reputação com barra de
  score, tráfego, top peers) + botão Localizar; fecha com ✕, fora ou Esc.
- **Comparador ⇄ (topo):** dois IPs → KPIs por direção, timeline bicolor com
  tooltip, top portas por direção.

### 3.3. Gaveta 🏆 (top talkers)

Botão fica vermelho se algum público verificado for não confiável. Uma seção, com
**5 itens/página**: top talkers (barras, clique localiza). ↻ recarrega (não é
automático de propósito, para não dobrar consultas pesadas). A verificação de
reputação foi para a aba **Cobertura** da tela de Reputação — uma tela só, sem
duas listas do mesmo dado.

### 3.4. Reputação 🚨 — página inteira (painel, base, cobertura)

Botão do topo que **trocou o mapa por uma página de largura toda** (a barra
lateral, o grafo e o painel de detalhe saem de cena; o topbar fica, porque é
de lá que se navega). "← mapa" no cabeçalho e `Esc` voltam. Virou página, e não
modal, porque a leitura é comparativa — faixa × contexto × país × dia precisa de
espaço lado a lado, não de uma caixa sobre o mapa.

Uma tela com **um único seletor de período** (24h / 7d / 30d / base inteira)
compartilhado pelas três abas, porque é o mesmo tempo nos dois lugares.

**Painel** (`GET /api/reputation/overview?days=N`) — a resposta às três perguntas
que o mapa não responde:

- **KPIs:** IPs públicos vistos, quantos têm score > 0, que % do byte foi para
  score > 0, cobertura (com veredito / sem veredito) e hosts internos que
  falaram com IP público.
- **Donut de score** em 8 faixas (0, 1-10, …, 91-100, sem veredito). O anel
  segue a ordem de score (é a ordem do AbuseIPDB e a que dá sentido à rampa de
  cor); a **lista ao lado é ranking**, do maior para o menor, como qualquer
  contagem. Clicar numa fatia **filtra a aba Base** daquela faixa — o filtro
  aparece no nome da aba e some com "limpar".
- **Contexto de uso** (classificação `usage_type` do AbuseIPDB): hospedagem /
  CDN / datacenter × operadora × institucional × sem classificação. É o corte que
  separa varredura e cloud de saída para C2.
- **Países e operadoras** com IP ruim (quem assina, não quem hospeda), do maior
  para o menor.
- **Bytes por dia** com dia fechado (`pair_daily`), barra empilhada: parte que foi
  para score > 0 em cima do total, com o percentual ruim acima de cada coluna.
- **Notas de honestidade:** de onde vieram os bytes, quantos dias fechados
  entraram, retenção pedida × disponível e lacunas na série diária.

**Base** (`GET /api/reputation/db?days=N&order=`) — o que já foi verificado no
Postgres (`ip_reputation`), cruzado com o histórico (`ip_sightings`). Mesmo
conteúdo de antes, agora dentro da tela única:

- **Por região:** países ordenados por nº de IPs problemáticos; clique abre a
  lista de IPs daquele país.
- **Ordenação:** score → denúncias → bytes → visto por último. Regiões e IPs
  nunca são reorderados na tela — a ordem do banco é a ordem mostrada (ordenar
  por score na interface exigiria re-consultar a API externa e queimar cota).
- **Por IP:** score, denúncias, bytes/fluxos acumulados, última denúncia,
  quando foi verificado, ISP/usage type/domínio.
- **Ações:** dossiê completo, histórico de 7/30 dias (`/api/lookup`), localizar
  no mapa.

**Cobertura** — o que o cache local já sabe sobre os IPs públicos **visíveis no
mapa na janela atual**, com a idade de cada veredito e o estado da cota. O botão
consulta **só o que não está em cache**; se a cota acabar, ele avisa e desliga em
vez de insistir.

⚠️ **O score é o de hoje, aplicado ao histórico.** Um IP visto há 30 dias aparece
com o score que tem agora. Isso é barato (não exige guardar score por dia) e é
aceitável para screening, mas não serve para provar o que o score era no momento
do fluxo.

⚠️ **`ip_sightings` é "IP público visto", não "origem maliciosa".** O coletor das
06:15 grava o IP público tanto como origem quanto como destino do fluxo. Por isso
"IPs públicos vistos" ≠ "quem acessou a rede".

### 3.4b. `ip_daily`: por que existe e como se recupera

`ip_sightings` guarda o **total por IP**. O valor por dia mora em `ip_daily`
(`day`, `ip`, `bytes`, `flows`, `first_ts`, `last_ts`) e o total é o rollup
disso: `sum(bytes)`, `min(first_ts)`, `max(last_ts)`.

Isso é uma correção, não uma escolha de modelagem. A versão anterior somava bytes
direto em `ip_sightings` a cada coleta (`bytes = ip_sightings.bytes +
excluded.bytes`). Só que o job das 06:15 usa janela de 24h e o botão de coleta
manual usava 168h: as duas janelas cobriam os mesmos dias, o mesmo byte era
somado de novo e a soma nunca voltava atrás. Medido antes da correção, os IPs de
maior volume apareciam com **3,53× a 5,26×** os bytes que o ES realmente tinha
(`pair_daily`, que nunca teve esse problema, era a referência).

Consequências do rollup:

1. **Regravação é idempotente.** Rodar a coleta duas vezes dá o mesmo número;
   `sum` só do que entrou no dia.
2. **`first_seen`/`last_seen` são avistamentos reais** (`min`/`max` de
   `@timestamp`), não a idade da janela no momento da coleta. Antes um IP visto
   há 2h "nascia" com 24h, e o rótulo `primeira-vez` da tela de destinos novos
   ficava sem sentido.
3. **Dia sem documento no ES é pulado**, nunca convertido em zero. Dia que
   expirou por retenção não pode parecer "esse IP não fez nada naquele dia".

**Limite honesto:** o ES guarda o fluxo bruto por pouco tempo. O que já expirou
lá não tem de onde voltar — `ip_sightings` só cobre, no máximo, a partir do
primeiro dia que ainda existe no ES. Reconstruir é `node
backend/scripts/rebuild-sightings.js --confirm`, que zera `ip_daily` +
`ip_sightings` (preservando `ip_reputation`, que é cache pago), reprocessa dia a
dia o que o ES tem, e refaz o backfill de `pair_daily`. Sem `--confirm` ele só
imprime o plano.

### 3.5. Exposição 🛡

Duas coisas que o mapa, sozinho, não responde: **para quem** o host está
falando e **quanto** disso é para IP ruim.

**Fórmula do risco** (`backend/src/risk.js`, `GET /api/risk`)

```
risco(host) = Σ(bytes_para_ip × score/100) ÷ bytes_totais_externos
```

- Só entram pares **interno → público**; tráfego interno→interno não conta
  (não é exposição a nada).
- O score pondera: 100 KB para IP nota 100 pesa 10× o mesmo volume para nota 10.
- Faixas: `<5%` baixo · `5–20%` médio · `20–50%` alto · `>50%` crítico · `0` sem
  exposição.
- **Cruza ES com Postgres, não chama a API externa.** Os bytes vêm da agregação
  por par; o score vem de `ip_reputation`, que já foi pago/consultado antes. Por
  isso a tela Exposição não gasta cota.

**Tela Exposição 🛡** (4 abas):

| Aba | Pergunta | Fonte |
|---|---|---|
| Risco por host | quanto do tráfego foi para IP com score>0 | ES × Postgres |
| Entrada | quais IPs públicos enviaram fluxo para a rede privada | ES, incluindo protocolos sem porta |
| Destinos novos | quais IPs públicos não constam no snapshot ou apareceram pela primeira vez | ES × `ip_sightings.first_seen` |
| Sessões vivas | quais pares tiveram fluxo recente | ES, `flowEnd` recente |

- **Destinos novos** mede novidade por IP de destino global, não por relação
  `origem→destino`. Primeira aparição dentro do histórico coletado é confirmada;
  IP ausente no snapshot diário é apenas candidato, pois a coleta atualiza em lote.
  A tela informa quando o snapshot foi atualizado.
- **Janela da tela**: risco, entrada, destinos novos e sessões seguem o seletor
  de tempo (ou o intervalo personalizado) e o cabeçalho mostra qual é.
- **Sessões vivas** não são "conexões abertas": NetFlow não tem estado. É o par
  que teve pacote nos últimos `activeSec` (padrão 120s), que é o mais perto de
  sessão que o formato permite. Duração = primeiro→último fluxo do par; bps só
  aparece quando a duração é > 0 (senão seria infinito/ruim).
- **Inventário de máquinas** (`servers`, `server_ips`, `applications`,
  `application_listeners`, `application_expected_clients`): uma máquina pode ter vários IPs; um listener associa
  uma aplicação a um IP, protocolo e porta. Os nomes cadastrados têm prioridade
  sobre o inventário JSON legado e rDNS no grafo e nos dossiês.

### 3.6. Série diária da tela de Reputação (`backend/src/daily.js`)

O ES guarda o fluxo bruto por pouco tempo. `pair_daily` guarda **bytes, pacotes e
fluxos por dia, par e porta de destino**, e nunca expira. A tela de Reputação soma
as portas; o relatório de acessos críticos usa `dport` para separar serviços.

| Parte | O que faz |
|---|---|
| `pair_daily` | tabela `(day, src, dst, proto, dport)` + PK; `dport=0` significa porta ausente ou histórica ainda não reprocessada |
| `harvestDaily()` | composite diário por origem/destino/protocolo/porta de destino → **apaga o dia e regrava** |

Decisões da série:

1. **Só dias fechados.** O job descarta o dia corrente porque ainda está
   crescendo; a série histórica da Reputação usa dias completos.
2. **Apagar-e-regravar, não somar.** Somar no `ON CONFLICT` pareceria natural,
   mas rodar o job duas vezes — ou um backfill sobreposto — contaria o mesmo
    byte duas vezes e distorceria os totais. Trocar o dia inteiro custa o
   mesmo e dá o resultado certo sempre. É o que torna o job idempotente.
3. **Só dias registrados entram na série.** Um dia sem linha pode significar
   que não houve fluxo ou que a coleta não rodou; a tela de Reputação sinaliza
    os dias disponíveis em vez de inventar um zero.

Depois da migração, reprocessar dias ainda retidos no ES para preencher `dport`:
`cd backend && node scripts/backfill-pair-daily-ports.js 30 --confirm`.
Histórico que já expirou no ES fica com porta desconhecida (`0`) e não pode ser
reconstruído a partir da tabela antiga.

### 3.6b. Fuso do "dia" dos relatórios (`backend/src/time.js`)

O `day` de `pair_daily` e `ip_daily`, a janela de acessos críticos e a série da
Reputação usam o **dia local** de `REPORT_TZ` (padrão `America/Fortaleza`), não o
dia UTC. Em UTC-3 o dia UTC fecha às 21h locais: a virada dos relatórios caía no
meio da noite e partia a janela de tráfego.

`time.js` expõe `localDay(date)` (YYYY-MM-DD no fuso), `todayLocal()`,
`dayRange(day)` (intervalo `[start, end)` do dia local como instantes UTC, com
`start` = 00:00 local e `end` = 00:00 do dia seguinte, exclusivo) e `addDays(day, n)`.
A coleta (`harvestDaily`, `harvestDia`) consulta o ES por esse intervalo
(`gte`/`lt`) em vez de `T00:00:00Z`..`T23:59:59.999Z`; o `generate_series` da Banda
em `7d`/`30d` e o `date_histogram` do dossiê `/api/ip` também passam a alinhar ao
dia local (`time_zone`).

**Migração:** as linhas já gravadas com dia UTC **não** são convertidas
automaticamente. Só os dias novos (e os reprocessados por backfill) passam a usar
o dia local, então pode haver um degrau de exibição entre o último dia UTC e o
primeiro local. Reprocessar dias ainda retidos no ES usa os backfills existentes
(`backfill-pair-daily-ports.js`, `rebuild-sightings.js`), ambos exigindo `--confirm`.

### 3.7. Acessos a serviços críticos

`GET /api/dashboard/critical-access?days=30` lista clientes que chegaram às
portas TCP 22, 445, 1433, 3389 e 5985 dos IPs inventariados. A primeira aparição
vem do menor dia em `pair_daily`; fluxos do dia corrente vêm diretamente do ES.
Um cliente só é marcado **fora do esperado** quando a aplicação tem uma allowlist
configurada em `application_expected_clients`; sem allowlist aparece **sem baseline**.
O `portHistoryStart` é o primeiro dia com `dport <> 0`, e `portHistoryDays` conta
os dias que já têm porta confiável. `pairFirstDay` agrega origem/destino/protocolo
ignorando porta, incluindo linhas antigas `dport=0`. `novelty` é `new` apenas quando
o par e a porta aparecem depois do começo da cobertura; `known-pair-new-port` indica
par anterior com porta nova; `baseline` significa que a primeira aparição coincide
com ou precede o começo da cobertura. `isNew` permanece como compatibilidade e só
é verdadeiro para `novelty=new`.

### 3.8. Firewalls FortiGate (`backend/src/fortigate.js`)

A tela **FortiGate** no topo cadastra firewalls (nome + IP/host + token da API) e
mostra as políticas com maior contagem de `hit_count`. Semana-semana:

1. **Tabela `fortigate`** guarda só o material cifrado de AES-256-GCM
   (`token_cipher`, `token_iv`, `token_tag`); a chave vive em `FORTIGATE_KEY`
   (env). A API devolve no máximo `hasToken=true` — nunca o token. Sem
   `FORTIGATE_KEY` configurada, criar/editar/testar FortiGate falha com erro
   explícito em vez de gravar em claro.
2. **Chamada HTTPS** a `{host}/api/v2/monitor/firewall/policy` com header
   `Accept: application/json` e `Authorization: Bearer <token>`. O certificado
   self-signed é ignorado (`rejectUnauthorized: false`), igual ao `curl -k` que
   validou o acesso; uma CA própria pode trocar isso mais tarde.
3. **Normalização** das policies: `hit_count`, `bytes`, `packets`,
   `active_sessions`, `session_count`, `first_used`/`last_used` e
   `session_first_used`/`session_last_used` (Unix). `bytes`/`packets` podem vir
   como número ou como objeto com os mecanismos de processamento
   (`software`/`asic`/`nturbo`); um objeto com chave `total` manda, senão as
   folhas somam. A série `1_week_ipv4` é preservada em `history`.
4. **Ordenação**: `hits` (padrão), `bytes`, `packets` ou `sessions`, com limite
   1–100. `POST /:id/test` busca 1 política só para validar conexão/token.

O fluxo é direto do FortiGate (sem cache): cada abertura/atualização da tela
reconsulta a API. Note que `hit_count` é um contador que só sobe enquanto a regra
tem tráfego, e `session_count` exposto pela API não é sessão ativa — a coluna
"ativas" vem de `active_sessions`.

**Período dos contadores:** `GET /api/v2/monitor/firewall/policy` não recebe
`from`/`to` nesta integração. `hit_count`, `bytes` e `packets` são os contadores
atuais do equipamento (podem ser zerados/resetados); `first_used`/`last_used`
também não representam um filtro selecionável. A série `1_week_ipv4` cobre só a
janela semanal devolvida pelo FortiOS. Por isso, zeros na tela significam que o
contador atual está em zero, não que a política nunca tenha sido usada nem que
não teve uso num mês específico.

Para resumir um intervalo histórico, o backend grava snapshots locais dos
contadores por política (padrão: `FORTIGATE_HISTORY_CRON=15 * * * *`) e soma as
diferenças entre amostras. A tela oferece 7/30/90 dias e datas de início/fim;
`GET /api/fortigate/:id/history?days=30` e `?from=YYYY-MM-DD&to=YYYY-MM-DD`
retornam hits/bytes/pacotes do período. Se o contador diminuiu entre amostras,
isso é contado como reset e sinalizado na coluna de resets. **Esse histórico
começa na primeira coleta local e não pode reconstruir retroativamente os 30
dias anteriores**; a tela informa a cobertura real até que haja amostras
suficientes. `POST /api/fortigate/:id/snapshot` coleta uma amostra imediata.
Snapshots são mantidos por `FORTIGATE_HISTORY_RETENTION_DAYS` (padrão 120 dias).

### 3.9. Análise de políticas (`backend/src/firewallAnalysis.js`)

A tela **FortiGate → Análise inteligente** não aplica nada no equipamento: só
produz sugestões justificadas. O motor determinístico (sem IA generativa) cruza
quatro fontes por política:

1. **Configuração** — `GET /api/v2/cmdb/firewall/policy?vdom=root`, a lista
   completa da CMDB **na ordem efetiva** (`position` = índice + 1). O `policyid`
   não diz a posição real da ACL.
2. **Uso** — o mesmo `monitor/firewall/policy` da tela (`hit_count`, `bytes`,
   `packets`, `active_sessions`, `first_used`/`last_used` e a série `1_week_ipv4`).
3. **Posição** efetiva na lista da CMDB.
4. **Tempo** — `last_used`/`first_used` e a série semanal.

Regras (cada achado traz `severity` da detecção, `confidence`, `impact`,
`changeRisk` da mudança, `evidence`, `recommendation` e `validation`):

- `unused` — contador de hits em zero (confiança média: pode ser sazonal/DR).
- `stale` — teve uso, mas o último hit passou de `staleDays` (padrão 90).
- `overly_permissive` — `accept` com `service=ALL` e origem/destino abrangentes.
- `service_all_specific_target` — destino específico, mas todos os serviços liberados.
- `no_inspection` — aceita sem UTM, sem perfis de segurança e com SSL/SSH sem inspeção.
- `no_description` — sem comentário (e nome curto).
- `high_usage_low_position` — muito usada, mas no quarto final da lista.
- `high_volume` — bytes acima do p90 das regras comparáveis.
- `duplicate` — mesma assinatura de encaminhamento/inspeção de outra regra.
- `traffic_shift` — série semanal com aumento/queda > 2× entre as metades.
- `counter_inconsistency` — série semanal com hits zerados mas bytes positivos.

`GET /api/fortigate/:id/analysis?staleDays=90` devolve `summary` (totais por
severidade), `findings` e `limitations`. **É consultivo**: nada é aplicado no
equipamento. Ainda não implementado (documentado no próprio endpoint): sombreamento/
precedência fina entre regras, objetos de endereço/serviço órfãos e mudança anormal
com snapshots históricos próprios.

### 3.10. Banda (`backend/src/dashboard.js`, `bandwidthForServer`)

A aba **Banda** do Dashboard mostra a série de bps de uma máquina, com
agrupamento por máquina, sub-rede, aplicação ou exportador. Pontos do item 3:

1. **Tempo pelo fim do fluxo.** O `date_histogram` usa
   `netflow.flowEndMilliseconds` (`F_FEND`), não `@timestamp` (hora de
   exportação, ~15s depois). O filtro ganha a margem `BANDWIDTH_TIME_MARGIN_MS`
   (padrão 120000) para não cortar a primeira borda; o `hard_bounds` do
   histograma corta os buckets da margem e o `extended_bounds` (com
   `min_doc_count: 0`) continua preenchendo os intervalos vazios da janela.
2. **P95 sobre 5 min.** Para `1h` os buckets de 1 min são agregados em amostras
   de 5 min só para o P95; `6h`/`24h` já usam intervalos de 5 min. Em `7d`/`30d`
   (fonte `pair_daily`, ponto diário) **não há P95** — a resposta devolve
   `averageDailyBitsPerSecond` e `peakDailyBitsPerSecond`, e a tela mostra
   "média diária" e "pico diário".
3. **Duplicidade/direção.** A duplicação **não** é filtrada antes de medir:
   `GET /api/diagnostics/duplication?minutes=5` pega os 20 pares com mais bytes
   e quebra os bytes por exportador (`host.ip`) e por `flowDirection`. Se o
   mesmo par aparece em vários exportadores ou em Ingress+Egress, os totais
   somam o mesmo tráfego 2x. A consulta de banda aplica
   `BANDWIDTH_FLOW_DIRECTION=both|ingress|egress` (padrão `both`), reaproveitando
   `addInventoryFlowFilter`.

---

## 4. Limitações conhecidas (não esconder)

1. **Ponto cego do exporter:** tráfego fora do switch monitorado não existe
   para o mapa (caso do Elasticsearch e do seu SSH no início).
2. **Direção do exporter nem sempre é intuitiva:** respostas volumosas podem vir
   atribuídas como origem (caso SQL `.2→.12` com dports efêmeras) — os rótulos
   `retorno` refletem o dado como ele vem.
3. **Sessão idle** só aparece quando o exporter exporta o fluxo (timeout ativo);
   ausência momentânea da :22 ≠ corte.
4. **Nomes:** sem PTR/inventário não há nome; "site exato" (youtube.com) é
   impossível só com NetFlow L3/L4 — o fingerprint é `*.googlevideo.com`/ASN.
5. **Reputação** = score do AbuseIPDB (0 limpo), não "garantido seguro"; depende
   da chave e da cota (cache 6h ajuda).
6. **Beacon/C2 é indicativo, não prova.** `/api/beacon` mede a regularidade dos
   intervalos de início de fluxo de um par. `cv < 0.35` é compatível com beacon,
   mas também com qualquer tráfego agendado (backup, cron, health check,
   sincronização de nuvem). É um sinal para investigar o par, nunca um veredito.
7. **O piso de 1s do exporter mascara beacon.** O VMware reexporta o fluxo no
   máximo a cada 1s, então nenhum par tem intervalo menor que isso. Isso infla o
   desvio e mantém o `cv` alto mesmo em tráfego que é claramente periódico —
   medido no ambiente real, `cv` nunca cai de ~0,58. Leia "irregular" como
   "não comprovado por esta medida", não como "descartado". Detecção real de
   beacon exigiria `tcpControlBits` (que existe no índice) e lógica de SYN/RST,
   não só cadência.
8. **Score ausente = desconhecido.** O risco usa scores recentes do
   `ip_reputation`; IP sem veredito atual não é tratado como limpo. A tela mostra
   cobertura parcial e separa desconhecidos de destinos avaliados.
9. **Duas armadilhas do cliente ES que custaram bugs reais** (documentadas
   porque vão aparecer de novo em qualquer campo novo):
   - `_source: ['netflow.x']` devolve o objeto **aninhado**
     (`{ netflow: { x } }`), não a chave `"netflow.x"`. Ler por índice direto
     dá `undefined` e a consulta parece "sem dados" em vez de dar erro. Use
     `srcField()`.
   - `netflow.flowStartMilliseconds` é **DATE ISO**, não epoch. Tratar como
     número zera a série em silêncio. Use `toMs()`, que aceita os dois.

