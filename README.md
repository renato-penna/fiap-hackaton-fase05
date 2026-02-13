# 🛡️ Cloud Architecture Security Analyzer

Análise automatizada de segurança de arquiteturas cloud usando **YOLO** para detecção de componentes e **STRIDE** para modelagem de ameaças.

## 📋 Visão Geral

Este projeto detecta componentes em diagramas de arquitetura cloud (AWS, Azure, GCP) e aplica a metodologia STRIDE para identificar ameaças e sugerir mitigações.

## 🏗️ Estrutura do Projeto

```
cloud-arch-security-mvp/
├── config/                     # Configurações centralizadas
│   └── settings.py
├── data/                       # Dados (ignorado no git)
│   └── diagrams/
├── models/                     # Pesos do modelo YOLO
│   └── best.pt
├── scripts/                    # Scripts utilitários
│   ├── analyze_dataset.py
│   └── prepare_dataset.py
├── sql/                        # Scripts SQL
│   └── init_db.sql
├── src/                        # Código fonte
│   ├── app.py                  # Interface Streamlit
│   ├── database.py             # Camada de persistência
│   ├── detection/              # Módulo de detecção YOLO
│   │   └── detector.py
│   ├── stride/                 # Módulo de análise STRIDE
│   │   ├── categories.py
│   │   ├── engine.py
│   │   └── knowledge_base.py
│   └── training/               # Módulo de treinamento
│       └── trainer.py
├── tests/                      # Testes automatizados
│   ├── test_detector.py
│   ├── test_knowledge_base.py
│   └── test_stride_engine.py
├── docker-compose.yml
├── Makefile
├── pyproject.toml
└── README.md
```

## 🚀 Quick Start

### 1. Instalação

```bash
# Clonar o repositório
git clone <repo-url>
cd fiap-hackaton-fase05

# Instalar dependências
pip install -e .

# Para desenvolvimento
pip install -e ".[dev]"
```

### 2. Configuração

<details>
<summary><strong>🐧 Linux / macOS</strong></summary>

```bash
# Copiar configurações de ambiente
cp .env.example .env

# Editar conforme necessário
nano .env
```

</details>

<details>
<summary><strong>🪟 Windows (PowerShell)</strong></summary>

```powershell
# Copiar configurações de ambiente
Copy-Item .env.example .env

# Editar conforme necessário
notepad .env
```

</details>

### 3. Modelo

Coloque o arquivo `best.pt` (modelo YOLO treinado) na pasta `models/`.

### 4. Banco de Dados (opcional)

> **Nota:** Se você deseja utilizar a funcionalidade de **histórico de análises**, é necessário que o PostgreSQL esteja em execução. Sem o banco de dados, o sistema não consegue armazenar nem recuperar análises anteriores.

<details>
<summary><strong>🐧 Linux / macOS</strong></summary>

```bash
# Subir PostgreSQL com Docker
make db-up
```

</details>

<details>
<summary><strong>🪟 Windows (PowerShell)</strong></summary>

```powershell
# Subir PostgreSQL com Docker
docker compose up -d
```

</details>

> **Não é necessário executar o script `init_db.sql` manualmente.** O `docker-compose.yml` já monta esse arquivo na pasta `/docker-entrypoint-initdb.d/` do container PostgreSQL, o que faz com que ele seja executado automaticamente na primeira vez que o container é criado. Basta subir o container e as tabelas serão criadas sozinhas.

### 5. Executar

<details>
<summary><strong>🐧 Linux / macOS</strong></summary>

```bash
# Via Makefile
make run

# Ou diretamente
streamlit run src/app.py
```

</details>

<details>
<summary><strong>🪟 Windows (PowerShell)</strong></summary>

```powershell
streamlit run src/app.py
```

</details>

## 🧪 Testes

<details>
<summary><strong>🐧 Linux / macOS (Make)</strong></summary>

```bash
# Executar testes
make test

# Com cobertura
make test-cov

# Linting
make lint

# Formatação
make format
```

</details>

<details>
<summary><strong>🪟 Windows (PowerShell)</strong></summary>

```powershell
# Executar testes
pytest

# Com cobertura
pytest --cov=src --cov-report=html

# Linting
ruff check src/ tests/ config/
ruff format --check src/ tests/ config/

# Formatação
ruff format src/ tests/ config/
ruff check --fix src/ tests/ config/
```

</details>

## 🔧 Treinamento

O treinamento do modelo foi realizado no **Google Colab** utilizando o notebook [`notebooks/train_colab.ipynb`](notebooks/train_colab.ipynb), que já contém todas as etapas de preparação e treinamento configuradas para rodar na GPU gratuita do Colab.

**Alternativa local (requer GPU):** Se você possui uma GPU com recursos suficientes, pode realizar o treinamento localmente:

```bash
# Preparar dataset
python scripts/prepare_dataset.py

# Analisar dataset (estatísticas e distribuição de classes)
python scripts/analyze_dataset.py

# Treinar modelo
python -m src.training.trainer --data path/to/data.yaml --epochs 30
```

## 📊 Categorias Detectadas

| Categoria | Exemplos |
|-----------|----------|
| Compute | EC2, Lambda, EKS, Fargate, Beanstalk, Cloud Run |
| Database | RDS, DynamoDB, Aurora, Redis, Cosmos DB, Firestore |
| Storage | S3, EBS, EFS, Glacier, Blob Storage, Cloud Storage |
| Network | VPC, CloudFront, Route 53, ELB, ALB, NLB, CDN |
| Security | WAF, KMS, GuardDuty, Shield, Secrets Manager, Firewall |
| Identity | IAM, Cognito, Active Directory Service |
| API Gateway | API Gateway, AppSync, Apigee |
| Messaging | SQS, SNS, EventBridge, Kinesis, Pub/Sub |
| Monitoring | CloudWatch, CloudTrail, X-Ray, Grafana, Prometheus |
| ML/AI | SageMaker, Rekognition, Comprehend, Vertex AI |
| DevOps | CodePipeline, CodeBuild, Jenkins, Terraform |
| Serverless | Amplify, Step Functions, AppFlow |
| Analytics | Athena, Glue, BigQuery, EMR |
| Groups | Availability Zone, Region |

##  Licença

MIT