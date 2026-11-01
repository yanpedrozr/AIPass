# AIPass

Projeto full-stack de gerenciador de senhas com análise de força por machine learning.

- **Backend:** Python + Flask (API REST em `http://localhost:5000/api`)
- **Frontend:** React + Vite (`http://localhost:5173`)

## Estrutura

```
TCC/
├── backend/
│   ├── app/
│   │   ├── __init__.py            # create_app(): registra blueprints e configura CORS
│   │   ├── config.py              # Configurações lidas do .env
│   │   ├── auth/                  # Cadastro, login, senha mestre      -> /api/auth
│   │   ├── crypto/                # Derivação de chave, AES-GCM e chaves em memória
│   │   ├── vault/                 # CRUD de credenciais do cofre       -> /api/vault
│   │   ├── password_generator/    # Geração de senhas seguras          -> /api/generator
│   │   ├── ml_analysis/           # Análise de força com scikit-learn  -> /api/analysis
│   │   └── breach_check/          # Vazamentos (HIBP) e similaridade   -> /api/breach
│   ├── requirements.txt
│   ├── .env.example
│   └── run.py                     # Ponto de entrada do servidor
└── frontend/
    ├── src/
    │   ├── components/            # Componentes reutilizáveis (modal, alertas, medidor de força...)
    │   ├── context/               # Sessão (AuthContext) e notificações (ToastContext)
    │   ├── hooks/                 # useVault (cofre + relatório) e useDebouncedValue
    │   ├── pages/                 # Telas (rotas)
    │   ├── services/              # Comunicação com a API (api.js)
    │   ├── utils/                 # Rótulos, formatação e área de transferência
    │   ├── App.jsx                # Rotas
    │   └── main.jsx
    ├── .env.example
    ├── index.html
    ├── package.json
    └── vite.config.js
```

Cada módulo do backend é um Blueprint Flask com `__init__.py` (declara o blueprint) e `routes.py` (rotas). As rotas de cada um estão na tabela de endpoints no fim deste arquivo.

## Pré-requisitos

- Python 3.10+
- Node.js 18+ e npm

## Rodando o backend

```powershell
cd backend

# 1. Criar e ativar o ambiente virtual
python -m venv venv
.\venv\Scripts\Activate.ps1        # Windows (PowerShell)
# source venv/bin/activate         # Linux/macOS

# 2. Instalar dependências
pip install -r requirements.txt

# 3. Configurar variáveis de ambiente
copy .env.example .env             # Linux/macOS: cp .env.example .env

# 4. Iniciar o servidor
python run.py
```

A API sobe em `http://localhost:5000`. Teste com `http://localhost:5000/api/health`.

> Se o PowerShell bloquear o `Activate.ps1`, execute uma vez:
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

## Rodando o frontend

Em outro terminal:

```powershell
cd frontend
npm install
copy .env.example .env             # Linux/macOS: cp .env.example .env
npm run dev
```

Acesse `http://localhost:5173`. Para conferir se o backend está no ar, abra `http://localhost:5000/api/health`.

## Interface (React)

O frontend usa só React e React Router, sem bibliotecas de componentes. O visual usa um tema escuro em todas as telas (as cores ficam em variáveis no topo de `src/index.css`) e se adapta ao celular.

| Rota | Tela | Login |
|------|------|-------|
| `/` | Início: apresentação do sistema em linguagem simples, sem a barra superior | não |
| `/sobre` | Como o AIPass funciona: os detalhes técnicos de cada recurso (criptografia, modelo, HIBP, similaridade, alertas e gerador) | não |
| `/cadastro`, `/entrar` | Criar conta e abrir o cofre. No cadastro, a força da senha mestra aparece enquanto ela é digitada | não |
| `/cofre` | Lista de credenciais com busca, mostrar/ocultar, copiar usuário e senha, criar, editar e excluir. Cada credencial mostra a gravidade do pior alerta dela, e o topo mostra um resumo da segurança do cofre | sim |
| `/seguranca` | Relatório de segurança: nota de 0 a 100, alertas com recomendações (filtráveis por gravidade), botão "Trocar senha" em cada alerta e tabela com força, vazamentos e similaridade de cada credencial | sim |
| `/gerador` | Gerador de senhas com comprimento, tipos de caractere e entropia | sim |
| `/analisar` | Analisa uma senha avulsa com os três analisadores (força, HIBP e similaridade) e dá um veredito | sim |

**Alertas em tempo real:** no formulário da credencial, a força da senha (Random Forest) é atualizada enquanto se digita, com 400 ms de espera para não mandar uma requisição por tecla. O botão "Gerar senha forte" preenche uma senha de 20 caracteres. Ao salvar, os alertas que o backend devolve aparecem na hora, com a opção "Trocar a senha agora". Se não houver alerta, o modal fecha com a mensagem "Nenhum problema de segurança encontrado".

**Cuidados de segurança na interface**

- **Sessão:** o token JWT fica no `sessionStorage`. Ele sobrevive a um F5, mas some ao fechar a aba. Sozinho, o token não abre o cofre depois do logout ou de um reinício do backend, porque a chave do cofre só existe na memória do servidor.
- **Bloqueio automático:** o cofre é bloqueado (logout, que apaga a chave do servidor) depois de **10 minutos sem atividade** e também quando o token expira. Qualquer resposta 401 leva de volta ao login com o motivo.
- **Área de transferência:** senhas copiadas são apagadas da área de transferência depois de **30 segundos**, a menos que outra coisa tenha sido copiada pelo app nesse meio-tempo.
- **Senhas fora da URL:** todas as análises enviam a senha no corpo de um `POST`. Todas as requisições usam `cache: "no-store"`.
- **Fonte sem ligaduras:** senhas aparecem em fonte monoespaçada com as ligaduras desligadas, para `>=` não virar `≥` nem `!=` virar `≠` (a Cascadia Code, padrão do Windows, faz isso).
- **Ações irreversíveis:** excluir uma credencial pede confirmação.

Para gerar a versão de produção: `npm run build` (saída em `frontend/dist/`).

## CORS

O CORS é configurado em `backend/app/__init__.py` com `flask-cors`, liberando as rotas `/api/*` para as origens definidas em `CORS_ORIGINS` no `backend/.env` (padrão: `http://localhost:5173`). Para permitir outras origens, separe-as por vírgula:

```
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

## Autenticação

A senha mestra **nunca é armazenada**. No cadastro, o backend gera um salt aleatório de 16 bytes por usuário e deriva um hash de 32 bytes com **PBKDF2-HMAC-SHA256** (600.000 iterações, recomendação da OWASP). No banco SQLite (`backend/instance/vault.db`) ficam apenas o usuário, o salt, o hash e o número de iterações. No login, a chave é derivada novamente com o mesmo salt e comparada com o hash salvo em tempo constante.

Após o login, a API devolve um token JWT, que deve ser enviado nas rotas protegidas:

```
Authorization: Bearer <access_token>
```

Exemplo de corpo para `/register` e `/login`:

```json
{ "username": "alice", "master_password": "minha-senha-mestra-forte" }
```

Regras: nome de usuário com 3 a 32 caracteres (`a-z`, `0-9`, `_`, `.`, `-`, sem diferenciar maiúsculas) e senha mestra com no mínimo 12 caracteres.

## Cofre de credenciais

Cada credencial tem `service`, `username` e `password`. Exemplo de corpo para `POST /api/vault`:

```json
{ "service": "Gmail", "username": "alice@gmail.com", "password": "S3nh@-do-Gmail!" }
```

Todas as rotas do cofre exigem o token JWT. Ao criar ou editar, a resposta traz também os alertas de segurança daquela senha (ver [Alertas e recomendações](#alertas-e-recomendações)).

**Como a criptografia funciona**

1. No cadastro, cada usuário recebe **dois salts diferentes**: um para o hash de login e outro para a chave do cofre.
2. No login, depois de validar a senha mestra, o backend deriva a **chave do cofre** (PBKDF2-HMAC-SHA256, 256 bits) com o salt do cofre.
3. A chave fica **somente na memória do servidor**, associada ao token (`jti`), até o token expirar ou o usuário fazer logout. Ela nunca vai para o banco, para o disco nem para o próprio token. Se o banco vazar, a chave não está lá.
4. Os três campos de cada credencial (`service`, `username` e `password`) são cifrados juntos com **AES-256-GCM**, usando um **nonce aleatório de 12 bytes exclusivo** por credencial. Um nonce novo é gerado também a cada edição. No banco ficam apenas o id, o dono, o nonce, o ciphertext e as datas: nada da credencial fica em texto puro.
5. O ciphertext é vinculado ao usuário e à credencial por meio de *dados associados* (AAD). Se alguém copiar dados cifrados para outra linha do banco, a decifragem falha.
6. Ao listar ou buscar, as credenciais são decifradas apenas em memória para montar a resposta, que é enviada com `Cache-Control: no-store`. Como o banco não enxerga o nome do serviço, a ordenação da lista também é feita em memória. Nenhum dado decifrado é registrado em log.

**Limitações conhecidas**

- Reiniciar o backend apaga as chaves da memória: os usuários precisam fazer login de novo.
- A implementação assume um único processo do servidor. Com vários workers, seria necessário um armazenamento compartilhado em memória (ex.: Redis).
- O tamanho do ciphertext revela aproximadamente o tamanho total dos três campos somados (característica do AES-GCM).

## Gerador de senhas

`/api/generator/generate-password` não exige login. As opções podem ir na query string (GET) ou no corpo JSON (POST):

| Opção       | Padrão | Descrição |
|-------------|--------|-----------|
| `length`    | `16`   | Comprimento, de 4 a 128 |
| `uppercase` | `true` | Letras maiúsculas (A-Z) |
| `lowercase` | `true` | Letras minúsculas (a-z) |
| `digits`    | `true` | Números (0-9) |
| `symbols`   | `true` | Caracteres especiais: os 32 símbolos ASCII de `string.punctuation`, como `!@#$%&*?` |

```
GET /api/generator/generate-password?length=24&symbols=false
```

```json
{
  "password": "k7GqT2mZr9XbWc4NpL8vYh3d",
  "entropy_bits": 142.88,
  "options": { "length": 24, "uppercase": true, "lowercase": true, "digits": true, "symbols": false }
}
```

A senha é gerada com o módulo `secrets` (gerador criptograficamente seguro do sistema operacional) e sempre contém pelo menos um caractere de cada categoria selecionada. Para garantir isso sem introduzir viés, todos os caracteres são sorteados do conjunto completo e a senha é descartada e sorteada de novo se faltar alguma categoria (amostragem por rejeição). Assim, toda senha válida tem a mesma probabilidade. `entropy_bits` é a entropia exata dessa distribuição.

## Análise de força: características da senha

`backend/app/ml_analysis/features.py` transforma cada senha em um vetor numérico para o modelo (a ordem das colunas está em `FEATURE_NAMES`):

| Atributo | Descrição |
|----------|-----------|
| `length`, `uppercase_count`, `lowercase_count`, `digit_count`, `special_count` | Comprimento e contagem por categoria |
| `entropy_bits` | `L * log2(N)` pelo conjunto de caracteres usado |
| `is_common_password` | 1 se a senha inteira está na lista de senhas comuns |
| `common_substring_length` | Maior trecho (4+ caracteres) que é uma senha da lista, ex.: `Dragon2024!` → 6 (`dragon`) |
| `sequence_length` | Maior sequência alfabética ou numérica, ex.: `abcd`, `4321` |
| `keyboard_sequence_length` | Maior sequência de teclas vizinhas na mesma linha, ex.: `qwerty`, `asdf`, `!@#$` |
| `repeated_char_length` | Maior repetição do mesmo caractere, ex.: `1111` |
| `contains_year` | 1 se contém um ano entre 1900 e 2099 |

Sequências e repetições só contam a partir de 3 caracteres (abaixo disso o valor é 0). A comparação com a lista ignora maiúsculas e desfaz substituições leet comuns (`@`→a, `0`→o, `3`→e, `$`→s...), então `P@ssw0rd` é reconhecida como `password`. Os dígitos no fim da senha são preservados, então `s3nh@123` é reconhecida como `senha123`.

As listas de senhas comuns são públicas, do [SecLists](https://github.com/danielmiessler/SecLists) (licença MIT), e ficam em `backend/app/ml_analysis/data/`: as 10.000 senhas mais comuns em geral e as 150 mais comuns em português (ex.: `123mudar`, `flamengo`, `deusefiel`). As duas são usadas juntas.

## Análise de força: rótulos de treino

`backend/app/ml_analysis/labels.py` rotula cada senha pelo score do [zxcvbn](https://github.com/dwolfhub/zxcvbn-python), que estima quantas tentativas seriam necessárias para adivinhá-la:

| Score zxcvbn | Tentativas estimadas | Rótulo | Código (`LabelEncoder`) |
|--------------|----------------------|--------|--------|
| 0 ou 1 | menos de 10^6 | `fraca` | 1 |
| 2 | menos de 10^8 | `média` | 2 |
| 3 ou 4 | 10^8 ou mais | `forte` | 0 |

O `LabelEncoder` do scikit-learn é ajustado sempre com os três rótulos fixos, então a codificação não muda de uma amostra para outra. Ele ordena as classes em ordem alfabética, por isso os códigos não seguem a ordem de força. Isso não afeta o Random Forest, que trata as classes como categorias.

A base de treino é uma amostra de 100.000 senhas da RockYou, sorteada da lista completa e **sem nenhuma senha das listas usadas nos atributos**, para evitar vazamento de dados (detalhes em `backend/app/ml_analysis/data/README.md`). Para gerar de novo:

```powershell
cd backend
# 1. Sortear a amostra (só se quiser trocá-la; precisa do rockyou.txt completo)
.\venv\Scripts\python.exe -m app.ml_analysis.dataset sample --rockyou caminho\rockyou.txt
# 2. Rotular a amostra e salvar data/training-labels.csv (~2 minutos)
.\venv\Scripts\python.exe -m app.ml_analysis.dataset label
```

## Análise de força: treinamento do Random Forest

`backend/app/ml_analysis/train.py` treina o modelo com a base rotulada:

```powershell
cd backend
.\venv\Scripts\python.exe -m app.ml_analysis.train    # ~10 segundos
```

1. Extrai os 12 atributos de cada senha e separa **80% para treino e 20% para teste**, de forma estratificada (mesma proporção de rótulos nos dois) e com semente fixa (42).
2. Treina um `RandomForestClassifier` com 100 árvores, `min_samples_leaf=10` e `class_weight="balanced"`. Esses parâmetros foram escolhidos por validação cruzada de 5 partes só no conjunto de treino: entre 50 e 300 árvores e 2 a 20 amostras por folha, o F1 macro ficou empatado (0,804 a 0,808, ±0,0035), então foi escolhida a configuração com modelo menor.
3. Avalia no conjunto de teste e salva em `backend/app/ml_analysis/models/`:
   - `password_strength_rf.joblib`: o modelo, o `LabelEncoder` e a lista de atributos (fora do git; gerado de novo com o comando acima)
   - `metrics.json`: todas as métricas abaixo

**Resultado no conjunto de teste (20.000 senhas):**

| Métrica | Valor |
|---------|-------|
| Acurácia | 80,9% (treino: 80,9%, sem overfitting) |
| F1 macro | 0,811 |
| Linha de base (sempre "média") | 36,5% |

| Classe | Precisão | Revocação | F1 |
|--------|----------|-----------|----|
| fraca | 0,888 | 0,761 | 0,819 |
| média | 0,770 | 0,750 | 0,760 |
| forte | 0,778 | 0,947 | 0,854 |

Os atributos mais importantes são `length` (41%), `entropy_bits` (23%) e `common_substring_length` (17%). `is_common_password` tem importância quase nula porque a base de treino exclui as senhas das listas (ver rótulos acima).

## Análise de força: rota `/api/analysis`

`POST /api/analysis` classifica a força de uma senha com o modelo treinado. Não exige login. A senha vai **só no corpo JSON** (a rota não aceita GET, para a senha nunca aparecer na URL), não é armazenada, não é registrada em log e não volta na resposta, que é enviada com `Cache-Control: no-store`.

```json
{ "password": "Dragon2024!" }
```

```json
{
  "strength": "forte",
  "probabilities": { "fraca": 0.133, "média": 0.2786, "forte": 0.5883 },
  "features": {
    "length": 11, "uppercase_count": 1, "lowercase_count": 5, "digit_count": 4,
    "special_count": 1, "entropy_bits": 72.1, "is_common_password": 0,
    "common_substring_length": 6, "sequence_length": 0, "keyboard_sequence_length": 0,
    "repeated_char_length": 0, "contains_year": 1
  }
}
```

- `strength`: o rótulo mais provável (`fraca`, `média` ou `forte`)
- `probabilities`: probabilidade de cada rótulo segundo o Random Forest
- `features`: os atributos extraídos, úteis para explicar o resultado (ex.: contém `dragon` e um ano)

| Situação | Status |
|----------|--------|
| Corpo que não é um objeto JSON, `password` ausente, vazia ou que não é texto | 400 |
| Senha com mais de 128 caracteres | 400 |
| Modelo ainda não treinado (`python -m app.ml_analysis.train`) | 503 |

O modelo é carregado do disco na primeira requisição e reaproveitado nas seguintes (≈5 ms por análise). `GET /api/analysis/status` informa se o modelo está disponível e quais atributos ele usa.

## Verificação de vazamentos (Have I Been Pwned)

`POST /api/breach` informa se uma senha aparece em vazamentos conhecidos, usando a API gratuita [Pwned Passwords](https://haveibeenpwned.com/API/v3#PwnedPasswords) do Have I Been Pwned (não precisa de chave). Não exige login.

```json
{ "password": "senha123" }
```

```json
{ "pwned": true, "count": 1128261 }
```

`count` é quantas vezes a senha apareceu nos vazamentos da base do HIBP (0 = nunca).

**A senha nunca sai do servidor (k-anonimato)**

1. O backend calcula o SHA-1 da senha (em UTF-8). Para `password`: `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`.
2. Só os **5 primeiros caracteres** do hash (`5BAA6`) são enviados: `GET https://api.pwnedpasswords.com/range/5BAA6`.
3. O HIBP devolve os finais de todos os hashes vazados com esse começo (centenas) e a contagem de cada um. A comparação com o final do hash da senha é feita localmente.
4. O cabeçalho `Add-Padding: true` faz o HIBP completar a resposta com entradas falsas (contagem 0, descartadas), para que nem o tamanho da resposta revele o prefixo.

Assim, nem o HIBP nem quem observa a rede consegue saber qual senha foi consultada. Como no restante da API, a senha vai só no corpo JSON (GET com a senha na URL é recusado), não é armazenada, não vai para log e não volta na resposta (`Cache-Control: no-store`).

| Situação | Status |
|----------|--------|
| Corpo que não é um objeto JSON, `password` ausente, vazia ou que não é texto | 400 |
| Senha com mais de 1024 caracteres | 400 |
| HIBP fora do ar, lento (mais que `HIBP_TIMEOUT_SECONDS`) ou respondendo com erro | 503 |

Configuração no `backend/.env` (valores padrão já funcionam):

```
HIBP_API_URL=https://api.pwnedpasswords.com
HIBP_TIMEOUT_SECONDS=5
HIBP_USER_AGENT=AIPass
```

A verificação de vazamentos complementa a análise por machine learning: `Dragon2024!` é classificada como `forte` pelo modelo, mas aparece 64 vezes em vazamentos no HIBP.

## Similaridade com senhas vazadas (IA)

O HIBP só encontra a senha **exata**. Ataques de dicionário, porém, testam variações de senhas vazadas: maiúsculas, leet, anos e símbolos no fim. `POST /api/breach/similarity` procura senhas vazadas **parecidas** com a senha informada. Não exige login, e o corpo é o mesmo das outras rotas:

```json
{ "password": "Dragon2024!" }
```

```json
{
  "risk": "alto",
  "similarity": 0.5637,
  "similar_passwords": [
    { "password": "drag0n", "similarity": 0.5637 },
    { "password": "dragon", "similarity": 0.5637 },
    { "password": "dragon2526", "similarity": 0.5362 },
    { "password": "dragon1", "similarity": 0.5339 },
    { "password": "dragons", "similarity": 0.5111 }
  ],
  "leaked_base": {
    "password": "dragon",
    "exact": false,
    "transformations": ["letras maiúsculas", "sufixo de 5 dígito(s)/símbolo(s)"]
  }
}
```

**Como funciona** (`backend/app/breach_check/similarity.py`)

1. **Base de senhas vazadas:** as 100.000 senhas da amostra da RockYou e as listas de senhas comuns do SecLists (≈110 mil senhas, as mesmas de `ml_analysis/data/`). Tudo roda localmente: a senha não sai do servidor.
2. **Vetorização TF-IDF:** cada senha vazada passa para minúsculas, tem o leet desfeito (`P@ssw0rd` → `password`) e vira um vetor TF-IDF de n-gramas de 2 a 4 caracteres (`TfidfVectorizer` do scikit-learn, `analyzer="char_wb"`, `sublinear_tf=True`). Os n-gramas capturam trechos em comum mesmo quando a senha tem letras trocadas, acrescentadas ou removidas.
3. **Busca pelos vizinhos mais próximos (k-NN):** a senha consultada é vetorizada do mesmo jeito e comparada com todas as vazadas pela **similaridade do cosseno** (de 0 a 1). As 5 mais próximas voltam em `similar_passwords`, e `similarity` é a maior delas.
4. **Palavra-base vazada:** verifica se a senha é uma senha vazada (ignorando maiúsculas e leet) com até 6 dígitos ou símbolos antes ou depois, como `dragon` + `2024!`. É a regra mais usada por ferramentas de quebra de senha como o hashcat. A base precisa ter pelo menos 4 caracteres, e é escolhida a maior possível (`S3nh@123!` → `senha123`, e não só `senha`). `exact` é `true` quando não há acréscimo nenhum (`Flamengo`, `p@ssw0rd`).

| `risk` | Critério |
|--------|----------|
| `alto` | Tem palavra-base vazada **ou** similaridade ≥ 0,70 |
| `médio` | Similaridade ≥ 0,45 |
| `baixo` | Similaridade < 0,45 |

Os limites foram calibrados com três grupos de 1.000 senhas:

| Grupo | Exemplo | `alto` | `médio` | `baixo` |
|-------|---------|--------|---------|---------|
| Variações de senhas vazadas (maiúsculas, leet, ano/símbolo no fim) | `Fl@meng01987!` | 100% | 0% | 0% |
| Senhas vazadas com uma letra trocada e dígitos no fim | `flamungo42` | 4,4% | 44,9% | 50,7% |
| Senhas aleatórias de 8 a 16 caracteres | `k7GqT2mZr9Xb!` | 0,1% | 2,6% | 97,3% |

`transformations` descreve como a senha difere da palavra-base sem repetir a senha: `letras maiúsculas`, `substituições leet`, `prefixo`/`sufixo` com o número de caracteres. A resposta traz senhas **da base de vazamentos** (dados públicos), mas nunca a senha consultada, e é enviada com `Cache-Control: no-store`.

| Situação | Status |
|----------|--------|
| Corpo que não é um objeto JSON, `password` ausente, vazia ou que não é texto | 400 |
| Senha com mais de 128 caracteres | 400 |
| Arquivos da base de senhas vazadas ausentes | 503 |

O índice é montado na primeira requisição (≈3 segundos) e reaproveitado nas seguintes (≈20 ms por consulta).

**Limitações:** a base local tem ≈110 mil senhas, contra centenas de milhões do HIBP, então uma senha pode ser parecida com uma senha vazada que não está na amostra. Frases-senha com palavras comuns (`correct horse battery staple`) podem dar risco `médio` por conterem palavras vazadas, mesmo sendo fortes pelo comprimento: por isso a análise complementa, e não substitui, a análise de força.

## Alertas e recomendações

Os três analisadores acima (força, vazamentos e similaridade) funcionam para uma senha avulsa. `backend/app/vault/security.py` aplica os três às credenciais do cofre e acrescenta o que nenhum deles vê sozinho: **senhas reutilizadas ou muito parecidas entre serviços do próprio usuário**, que é o que permite o credential stuffing (uma senha vazada num serviço é testada automaticamente nos outros).

### Relatório completo: `GET /api/vault/security-report`

Exige o token JWT. As credenciais são decifradas só em memória, como na listagem, e cada senha **distinta** é analisada uma vez: senhas repetidas não geram consultas repetidas ao HIBP. As consultas ao HIBP rodam em paralelo (até 8) e continuam usando k-anonimato.

```json
{
  "summary": {
    "credentials": 3, "at_risk": 3, "score": 0,
    "alerts_by_severity": { "crítico": 1, "alto": 2, "médio": 1, "baixo": 0 }
  },
  "alerts": [
    {
      "severity": "crítico", "type": "breached",
      "credential_ids": ["6f1c..."], "services": ["Gmail"],
      "message": "A senha de Gmail apareceu 1.128.261 vez(es) em vazamentos conhecidos. Troque agora.",
      "recommendation": "Troque a senha no site do serviço por uma nova, criada pelo gerador, e não a use em nenhum outro lugar."
    },
    {
      "severity": "alto", "type": "reused",
      "credential_ids": ["6f1c...", "a93e..."], "services": ["Gmail", "Facebook"],
      "message": "Gmail e Facebook usam a mesma senha.",
      "recommendation": "Se um desses serviços vazar, atacantes testam a mesma senha nos outros (credential stuffing). Use uma senha diferente para cada serviço."
    }
  ],
  "credentials": [
    { "id": "6f1c...", "service": "Gmail", "username": "alice@gmail.com", "severity": "crítico",
      "strength": "fraca", "pwned_count": 1128261, "leak_similarity": "alto", "alerts": 3 }
  ],
  "checks": { "strength": true, "breach": true, "similarity": true }
}
```

- `summary.score`: porcentagem de credenciais sem alerta crítico, alto ou médio (100 = cofre sem problemas).
- `credentials`: situação de cada credencial (a gravidade do pior alerta dela), para a interface marcar a lista.
- `checks`: `false` indica que um analisador não rodou para alguma senha (HIBP fora do ar, modelo não treinado). O relatório sai mesmo assim, com os outros analisadores.

| Tipo (`type`) | Gravidade | Quando |
|---------------|-----------|--------|
| `breached` | crítico | A senha aparece no HIBP |
| `reused` | alto | Duas ou mais credenciais usam exatamente a mesma senha |
| `leak_variation` | alto | Risco `alto` na similaridade com vazamentos (ex.: `Dragon2024!`), se a senha exata não estiver no HIBP |
| `weak` | alto (`fraca`) ou médio (`média`) | Classificação do Random Forest, com os motivos tirados dos atributos: "tem só 8 caracteres", "contém um ano", "contém uma sequência de teclado"... |
| `similar` | médio | Senhas de credenciais diferentes muito parecidas (ex.: `SenhaForte!Gmail` e `SenhaForte!Face`) |
| `leak_similarity` | baixo | Risco `médio` na similaridade com vazamentos |
| `short` | baixo | Classificada como `forte`, mas com menos de 12 caracteres |

Os alertas saem do mais grave para o menos grave. Um alerta de grupo (`reused`, `similar`) cita todas as credenciais envolvidas. Quando há mais de uma credencial do mesmo serviço, o nome vem acompanhado do usuário: `Gmail (trabalho@gmail.com)`.

**Senhas muito parecidas:** duas senhas do usuário ficam no mesmo grupo quando a similaridade do cosseno entre os vetores TF-IDF (o mesmo vetorizador da similaridade com vazamentos) é de pelo menos **0,6**, ou quando têm a mesma palavra-base vazada (`dragon2024` e `dr4g0n!`). A ligação é transitiva: `casa1234!`, `casa1235!` e `casa1236!` formam um único grupo. O limite foi escolhido com pares de exemplo:

| Par | Cosseno | Resultado |
|-----|---------|-----------|
| `Gmail2023!` / `Gmail2024!` | 0,73 | parecidas |
| `SenhaForte!Gmail` / `SenhaForte!Face` | 0,68 | parecidas |
| `MinhaSenha#Banco` / `MinhaSenha#Netflix` | 0,62 | parecidas |
| `Gmail2023!` / `Brasil2023!` | 0,53 | diferentes |
| `Maria2020` / `Mario2021` | 0,35 | diferentes |
| 3.000 pares aleatórios da RockYou | máx. < 0,6 | nenhum par parecido |
| 2.000 pares de senhas aleatórias de 16 caracteres | máx. 0,22 | nenhum par parecido |

### Alertas em tempo real: `POST /api/vault` e `PUT/PATCH /api/vault/<id>`

A mesma lógica roda ao salvar uma credencial. A resposta traz a credencial e, junto, os alertas **daquela credencial**:

```json
{
  "credential": { "id": "a93e...", "service": "Facebook", "username": "alice", "password": "...", "...": "..." },
  "alerts": [
    { "severity": "alto", "type": "reused", "services": ["Facebook", "Gmail"],
      "message": "Facebook e Gmail usam a mesma senha.", "...": "..." }
  ],
  "checks": { "strength": true, "breach": true, "similarity": true }
}
```

Só a senha salva é analisada (uma consulta ao HIBP). Ela é comparada com as outras credenciais do usuário para detectar reutilização, sem nenhuma chamada externa para elas. Se o HIBP estiver fora do ar, a credencial é salva normalmente e `checks.breach` vem `false`.

**Privacidade:** nenhum alerta contém a senha. As mensagens citam o serviço, a contagem de vazamentos e o tipo de transformação ("sufixo de 5 dígito(s)/símbolo(s)"), nunca a palavra-base nem o sufixo em si. Nada é registrado em log.

## Testes

```powershell
cd backend
.\venv\Scripts\python.exe -m unittest -v
```

Os testes do gerador (`backend/tests/test_password_generator.py`) verificam:
- **Critérios:** comprimento, presença de cada categoria selecionada e ausência das não selecionadas, em todas as 15 combinações de categorias e em vários comprimentos. Também verificam a rejeição de opções inválidas.
- **Aleatoriedade:** uso de `secrets` (e não de `random`), ausência de senhas repetidas, frequência uniforme dos caracteres (teste qui-quadrado), ausência de correlação entre senhas consecutivas e categorias sem posições fixas.
- **Entropia** e o **endpoint** HTTP.

Os testes do cofre (`backend/tests/test_vault.py`) usam um banco SQLite temporário, recriado a cada teste, e verificam:
- **CRUD:** criar, listar (ordenado por serviço), buscar, editar parcialmente, excluir, validação dos campos e exigência de token.
- **Criptografia:** nenhum campo (`service`, `username`, `password`) aparece em texto puro no arquivo do banco. Cada credencial tem nonce único de 12 bytes, e um nonce novo é gerado a cada edição. Dados cifrados copiados para outra linha ou adulterados são rejeitados.
- **Chave do cofre:** fica só em memória. Não aparece no token nem no banco, é independente do hash de login, é derivada igual em um novo login e é apagada no logout.
- **Isolamento:** um usuário não lê, edita nem exclui credenciais de outro.
- **Logs:** nenhum dado da credencial nem a senha mestra aparecem nos logs, inclusive no SQL com parâmetros.

Os testes das características (`backend/tests/test_features.py`) verificam o carregamento das listas públicas (geral e em português), a detecção de senhas comuns (com maiúsculas e leet), trechos da lista dentro da senha, sequências alfabéticas, numéricas e de teclado, repetições, anos e a ordem do vetor.

Os testes dos rótulos (`backend/tests/test_labels.py`) verificam a faixa de score de cada rótulo, a codificação fixa do `LabelEncoder` (ida e volta), a amostragem (exclusão das listas dos atributos, sem repetição, reprodutível pela semente e espalhada pelo arquivo todo), a leitura da RockYou, a ausência de senhas das listas na amostra salva e o CSV rotulado (senhas como `null` e `NaN` continuam texto).

Os testes do treinamento (`backend/tests/test_train.py`) treinam um modelo pequeno numa pasta temporária e verificam a divisão estratificada, o desempenho acima da linha de base, o arquivo de métricas, o carregamento do modelo salvo (e a recusa de um modelo treinado com outros atributos) e a classificação de casos óbvios pelo modelo do projeto.

Os testes da rota de análise (`backend/tests/test_analysis_route.py`) verificam o formato da resposta, casos óbvios, que a senha não volta na resposta nem é aceita na URL, a validação da entrada, o limite de tamanho, o carregamento único do modelo e a resposta 503 quando o modelo não existe.

Os testes da verificação de vazamentos (`backend/tests/test_breach_check.py`) simulam a API do HIBP e verificam o hash SHA-1, a leitura da resposta (descartando o preenchimento), que **só o prefixo de 5 caracteres é enviado**, os cabeçalhos, o tratamento de falhas de rede e de erros HTTP (503), a validação da entrada e que a senha não é aceita na URL. Há também dois testes com a API real, desativados por padrão por dependerem de internet:

```powershell
$env:HIBP_LIVE_TESTS = "1"; .\venv\Scripts\python.exe -m unittest tests.test_breach_check -v
```

Os testes da similaridade (`backend/tests/test_similarity.py`) usam uma base pequena para verificar a normalização, a ordenação dos vizinhos, a palavra-base (com prefixo, sufixo, leet, limite de acréscimo e escolha da maior base), o risco, as transformações, que a senha não volta na resposta e a rota (validação, senha fora da URL e 503 sem a base). Também usam a base real para conferir que variações conhecidas (`Dragon2024!`, `S3nh@123!`) dão risco alto e senhas aleatórias não.

Os testes dos alertas (`backend/tests/test_security_report.py`) usam o cofre de teste com o HIBP simulado e verificam cada tipo de alerta e sua gravidade, a ordenação, o resumo, a identificação de serviços repetidos, que **nenhuma senha aparece na resposta**, que só o prefixo do hash vai ao HIBP e que senhas repetidas são consultadas uma vez, o relatório com o HIBP fora do ar, senhas muito longas, o isolamento entre usuários, os alertas ao criar e editar (só da credencial salva, com uma única consulta ao HIBP) e os grupos de senhas parecidas (inclusive pares que não devem ser agrupados). Os testes do cofre (`test_vault.py`) também simulam o HIBP, então nenhum teste usa a rede, exceto os dois ao vivo citados acima.

Para rodar só um arquivo de testes:

```powershell
.\venv\Scripts\python.exe -m unittest tests.test_vault -v
```

## Endpoints atuais

| Método | Rota                     | Descrição                 |
|--------|--------------------------|---------------------------|
| GET    | `/api/health`            | Verifica se a API está no ar |
| POST   | `/api/auth/register`     | Cadastra usuário com senha mestra |
| POST   | `/api/auth/login`        | Valida a senha mestra e retorna um token JWT |
| GET    | `/api/auth/me`           | Dados do usuário logado (requer token) |
| POST   | `/api/auth/logout`       | Encerra a sessão e apaga a chave do cofre da memória |
| GET    | `/api/vault`             | Lista as credenciais (senhas decifradas) |
| POST   | `/api/vault`             | Cria uma credencial (a resposta traz os alertas dela) |
| GET    | `/api/vault/security-report` | Alertas e recomendações de todo o cofre |
| GET    | `/api/vault/<id>`        | Busca uma credencial |
| PUT/PATCH | `/api/vault/<id>`     | Edita uma credencial (a resposta traz os alertas dela) |
| DELETE | `/api/vault/<id>`        | Exclui uma credencial |
| GET    | `/api/crypto/status`     | Placeholder do módulo     |
| GET/POST | `/api/generator/generate-password` | Gera uma senha forte |
| POST   | `/api/analysis`          | Classifica a força de uma senha (fraca, média ou forte) |
| GET    | `/api/analysis/status`   | Informa se o modelo de análise está carregado |
| POST   | `/api/breach`            | Verifica se uma senha aparece em vazamentos (HIBP) |
| POST   | `/api/breach/similarity` | Procura senhas vazadas parecidas (TF-IDF + k-NN) |
| GET    | `/api/breach/status`     | Informa o provedor da verificação de vazamentos |
