# 🕸️ Teia de Aranha — NetFlow VMware

Mapa visual de onde cada host está conectado. Backend consulta o Elasticsearch (`netflow-*` via NetFlow do VMware) e o frontend desenha com Cytoscape.js.

> 📖 Lógicas e detalhes completos em **[COMO-FUNCIONA.md](./COMO-FUNCIONA.md)**.

## Estrutura

```
backend/   Node + Express + @elastic/elasticsearch
frontend/  React + Vite + Cytoscape.js
```

## 1. Backend

```bash
cd backend
cp .env.example .env   # ajuste ELASTIC_URL / USER / PASS
npm install
npm run dev            # http://localhost:3001
```

Variáveis (`.env`):

| var | padrão | descrição |
|---|---|---|
| ELASTIC_URL | http://localhost:9200 | URL do Elasticsearch |
| ELASTIC_USER / ELASTIC_PASS | — | basic auth (opcional) |
| ELASTIC_API_KEY | — | alternativa ao basic auth |
| ELASTIC_INDEX | netflow-* | índice NetFlow |
| PORT | 3001 | porta do Express |
| MAX_EDGES | 50000 | teto de buckets por mapa/host; `0` desliga o limite |
| MAX_SPORT_BUCKETS | 10000 | teto menor para detalhes com porta de origem (host/dossiê/comparador) |
| COMPOSITE_PAGE_SIZE | 1000 | página da agg composite |
| ELASTIC_MAX_CONCURRENT_SEARCHES | 3 | buscas ES simultâneas por processo |
| ELASTIC_MAX_QUEUED_SEARCHES | 24 | fila máxima antes de responder 503 quando o ES está ocupado |
| ELASTIC_SEARCH_QUEUE_TIMEOUT_MS | 15000 | tempo máximo na fila do ES |
| ELASTIC_MAX_RETRIES | 1 | tentativas adicionais do cliente ES |
| ELASTIC_REQUEST_TIMEOUT_MS | 120000 | timeout da requisição ES após a conexão |
| ELASTIC_SLOW_SEARCH_WARN_MS | 30000 | registra no backend consultas ES lentas a partir deste tempo |
| MAX_SPORT_BUCKETS | 10000 | limite menor em detalhes que incluem porta de origem |
| DAILY_REFRESH_DAYS | 3 | janela reprocessada pelo cron diário (2 dias fechados; permite atraso do exporter) |
| DAILY_COMPOSITE_PAGE_SIZE / DAILY_MAX_COMPOSITE_PAGES | 5000 / 40 | limites do backfill diário (até 200 mil buckets/dia) |
| BANDWIDTH_FLOW_DIRECTION | both | direção contada na Banda: `both`, `ingress` ou `egress` (decida pelo `/api/diagnostics/duplication`) |
| BANDWIDTH_TIME_MARGIN_MS | 120000 | margem do filtro de tempo da Banda (a série usa o fim do fluxo) |
| FORTIGATE_KEY | — | chave do AES-256-GCM que cifra o token da API do FortiGate no Postgres (64 hex ou passphrase) |
| FORTIGATE_TIMEOUT_MS | 8000 | timeout das chamadas HTTPS ao FortiGate |
| REPORT_TZ | America/Fortaleza | fuso dos "dias" das séries diárias (`pair_daily`, `ip_daily`, acessos críticos, série da Reputação) |

> **Fuso dos relatórios:** o "dia" das séries diárias é o **dia local** (`REPORT_TZ`), não UTC — em UTC-3 o dia virava às 21h. Só os dias novos passam a usar o dia local; as linhas **já gravadas** em dia UTC **não** são migradas automaticamente (reprocessar dias ainda retidos no ES é possível via backfill, ver abaixo). Por isso, ao trocar o fuso, pode haver um degrau entre o último dia UTC e o primeiro local.

Endpoints:

- `GET /api/health` — ping no ES e estado da fila global de buscas (`active`, `queued`, `maxConcurrent`)
- `GET /api/graph?minutes=15` — grafo Cytoscape `{ nodes, edges, meta }`
  - ou `?minutes=5|60`, `?range=now-1h`, `?from=ISO&to=ISO`
- `GET /api/host/:ip?minutes=15` — detalhe do nó (in/out bytes, peers, portas, protocolos); `&active=1` mostra só conexões com pacote nos últimos `ACTIVE_WINDOW_SEC` (padrão 120s); cada peer traz `active`, `firstSeen` (primeira vista **na janela**) e `lastSeen`
- `GET /api/alerts?minutes=15` — top talkers da janela (`ALERT_TOP_N`, padrão 10)
- `POST /api/resolve {ips}` — nomes (inventário PostgreSQL + JSON legado + rDNS), ASN/org de IPs públicos e sub-redes
- `/api/inventory` — GET/POST/PATCH/DELETE para máquinas, IPs e aplicações/listeners. O frontend tem o botão **Inventário** no topo.
- `GET /api/dashboard/applications?serverId=...&minutes=15` e `GET /api/dashboard/ports?...` — top 5 por fluxos NetFlow da máquina selecionada; a aba Portas considera somente a porta local do servidor.
- `GET /api/dashboard/bandwidth?serverId=...&period=1h&groupBy=server` — série bps, média, pico e P95; `groupBy` aceita `server`, `subnet`, `application` ou `exporter`. Períodos `1h`, `6h`, `24h` usam ES; `7d`, `30d` usam `pair_daily` para máquina/sub-rede. A série é histogramada pelo **fim do fluxo** (`netflow.flowEndMilliseconds`, com margem de `BANDWIDTH_TIME_MARGIN_MS`), não pela hora de exportação. O P95 é sempre sobre **amostras de 5 min** (os pontos de 1 min são agregados de 5 em 5); em `7d`/`30d` (ponto diário) não há P95, só média e pico diários. A direção é filtrada por `BANDWIDTH_FLOW_DIRECTION`.
- `GET /api/diagnostics/duplication?minutes=5` — para os 20 pares com mais bytes, devolve os bytes por exportador (`host.ip`) e por `flowDirection`. Serve para decidir `BANDWIDTH_FLOW_DIRECTION`: se o mesmo par aparece em mais de um exportador ou em Ingress+Egress, os totais de banda somam o mesmo tráfego 2x. Não filtra direção (medir é o objetivo).
- `GET /api/dashboard/critical-access?days=30` — clientes das portas TCP críticas (22, 445, 1433, 3389, 5985), primeira/última aparição e comparação com allowlist por aplicação. A resposta devolve `portHistoryStart`, dias cobertos e `novelty` (`new`, `known-pair-new-port`, `baseline`); `isNew` só é verdadeiro para `new`.
- `GET /api/dashboard/conversations?top=5&time=1h&flowType=ingress` — top 1–20 conversas envolvendo IPs do inventário; `time` aceita `1h`, `6h` ou `24h`, e `flowType` aceita `ingress`, `egress` ou `both`. SYN/SYN-ACK orientam cliente/servidor quando observados; `flowDirection` é retornado como direção no exportador.
- `/api/fortigate` — GET/POST/PATCH/DELETE de firewalls FortiGate. O token é cifrado com AES-256-GCM (`FORTIGATE_KEY` no servidor) e a API só devolve `hasToken`, nunca o valor. `GET /api/fortigate/:id/policies?limit=20&sort=hits&offset=0` consulta `GET /api/v2/monitor/firewall/policy` (header `Authorization: Bearer`, TLS ignorado como curl `-k`) e devolve as políticas ordenadas por `hits`, `bytes`, `packets` ou `sessions`, com paginação por `offset` (a resposta traz `total`, `page` e `pages`); `POST /api/fortigate/:id/test` verifica conectividade e quantidade de políticas. `GET /api/fortigate/:id/analysis?staleDays=90` cruza a configuração (CMDB `firewall/policy`, na ordem efetiva) com o uso (monitor) e devolve sugestões justificadas (`severity`, `confidence`, `impact`, `changeRisk`, `evidence`, `recommendation`, `validation`); é somente leitura e não aplica nada no equipamento.
- `POST /api/reputation {ips}` — reputação de IPs públicos só via AbuseIPDB: 🟢 confiável (score 0) / 🔴 não confiável (score > 0); sem chave = não verificado. Só gasta cota no que não está no cache (6h em memória, 7 dias no Postgres — alimentado pela coleta diária das 06:15)
- `POST /api/reputation/coverage {ips}` — o que já está no cache, com a idade de cada veredito e o estado da cota; **não** chama o AbuseIPDB (é o que faz o botão "Verificar N IPs sem cache" só consultar o que falta)
- `GET /api/reputation/overview?days=1|7|30|0` — painel da tela de Reputação: IPs públicos vistos no período, quantos têm score > 0, % do byte que foi para score > 0, cobertura (com/sem veredito), faixa de score (donut), contexto de uso (hospedagem × operadora × institucional), países/ISPs com IP ruim e bytes por dia. O score é o de hoje aplicado ao histórico; bytes de 24h vêm do ES e de 7/30/base de `pair_daily` (só dia fechado)
- `GET /api/reputation/db?days=0&order=rep` — base de reputação: IPs já verificados + histórico de conexões, agrupados por país. É a aba "Base" da tela de Reputação (um seletor de período só, compartilhado entre as abas)
- `GET /api/ip/:ip?minutes=15` — dossiê completo: identidade (PTR, ASN/org, prefixo, sub-rede), reputação (score, reportes, país, ISP, domínio, whitelist) e tráfego na janela (in/out, top peers, top portas)
- `GET /api/compare?a=IP&b=IP&minutes=60` — comparador: bytes/fluxos por direção, timeline e top portas do par
- `GET /api/top-pairs?minutes=60` — top 10 pares bidirecionais (bytes, fluxos, protocolos, top portas)
- Coleta diária (06:15, `REGIONS_CRON`) + `POST /api/stats/harvest` — varre o ES, consulta a reputação de cada IP público novo e grava `ip_daily` (bytes/fluxos **por dia local**, `REPORT_TZ`) + `ip_sightings` (rollup: total por IP, país, primeiro/último avistamento). É o que alimenta risco, destinos novos e a base de reputação (botão "⇅ coletar base"). Regravar é idempotente: rodar a coleta duas vezes dá o mesmo número, porque a média do dia é substituída em vez de somada. Reconstrução: `node backend/scripts/rebuild-sightings.js --confirm` (sem a flag, só imprime o plano). A série diária de pares (`pair_daily`, 06:40) alimenta o gráfico diário da tela de Reputação; ao subir, o backend refaz os dias fechados que faltarem. A tela de Regiões foi removida: ela duplicava essa base.
- Sub-redes monitoradas (`/api/subnets`): cadastrar CIDR, nome e qual é a padrão — alimenta o filtro do mapa e o "abre junto com o sistema". (`watched_subnets` no Postgres)

A série `pair_daily` agora guarda `(dia, origem, destino, protocolo, porta_destino)`. A migração preenche `dport=0` nas linhas antigas; reprocese dias ainda retidos no Elasticsearch com `cd backend; node scripts/backfill-pair-daily-ports.js 30 --confirm` (use `DAILY_MAX_DAYS=90` para um backfill maior). O relatório crítico consulta o histórico port-aware; dias que já expiraram do ES só podem ser reconstruídos se ainda estiverem disponíveis em outra fonte.

A agregação do mapa usa composite `origem + destino`, estendida com `protocolo` e `porta_dest` para colorir as linhas e mostrar portas no clique. Paginação via `after_key` **sem teto** (até esgotar). A porta de origem efêmera fica fora do grafo/alertas (explodia os buckets e cortava pares) e entra só no detalhe do host, que é filtrado por IP. O mapa desenha **1 aresta por par + protocolo** (porta de serviço no rótulo, `retorno` quando só há efêmeras); portas de serviço (≤1023 + `KNOWN_SERVICE_PORTS`) aparecem primeiro nas listas.

## 2. Frontend

```bash
cd frontend
npm install
npm run dev   # http://localhost:5173 (proxy /api -> 3001)
```

Interface:

- **Nós:** IPs das VMs/servidores
- **Inventário:** máquina com um ou mais IPs; aplicações podem declarar listeners por IP, protocolo e porta. O nome do inventário é usado no mapa e nos dossiês.
- **Linhas:** conexões (seta origem → destino)
- **Espessura:** volume de bytes (escala log 1–10px)
- **Cor:** protocolo (TCP azul, UDP verde, ICMP amarelo, outros cinza)
- **Preenchimento do nó:** hosts internos em ciano; IPs públicos por score AbuseIPDB (>70 vermelho, 51–70 laranja, 20–50 amarelo, <20 verde; sem avaliação cinza)
- **Clique no IP:** painel lateral com total in/out, pacotes, top peers, portas e protocolos
- **Filtros:** 5 / 15 / 60 min ou intervalo personalizado + filtro por protocolo, bytes mínimos e busca de IP
- **Tela principal:** Dashboard (Aplicações, Portas, Banda, Acessos críticos e Tráfego das máquinas do inventário). Banda mostra média, pico e P95; Acessos críticos compara clientes observados com a allowlist por aplicação; Tráfego aceita top 1–20, período 1h/6h/24h e fluxo Ingress/Egress/Both. O Mapa fica no último item da navegação.
- **Outras telas e ações:** Inventário · Reputação (página inteira: painel + base + cobertura) · Exposição externa (risco, entrada, destinos novos e sessões) · sub-redes monitoradas · alertas · **FortiGate** (cadastro de firewalls com token cifrado + ranking de políticas por hits/bytes/pacotes/sessões com 1ª/última utilização + **análise inteligente** consultiva: regras obsoletas, permissivas demais, sem inspeção/descrição, redundantes, volume/posição e mudança de padrão, com evidência e o que validar antes de mudar)

## 3. Teste rápido sem ES

Se o Elasticsearch ainda não estiver acessível, suba com mock:

```bash
# backend devolve erro 500 com "Falha ao consultar Elasticsearch"
curl "http://localhost:3001/api/health"
curl "http://localhost:3001/api/graph?minutes=15"
```
