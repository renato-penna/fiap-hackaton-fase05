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
cd cloud-arch-security-mvp

# Instalar dependências
pip install -e .

# Para desenvolvimento
pip install -e ".[dev]"
```

### 2. Configuração

```bash
# Copiar configurações de ambiente
cp .env.example .env

# Editar conforme necessário
nano .env
```

### 3. Modelo

Coloque o arquivo `best.pt` (modelo YOLO treinado) na pasta `models/`.

### 4. Banco de Dados (opcional)

```bash
# Subir PostgreSQL com Docker
make db-up

# Executar script de inicialização
psql -h localhost -U postgres -d security_analyzer -f sql/init_db.sql
```

### 5. Executar

```bash
# Via Makefile
make run

# Ou diretamente
streamlit run src/app.py
```

## 🧪 Testes

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

## 🔧 Treinamento

```bash
# Preparar dataset
python scripts/prepare_dataset.py

# Treinar modelo
python -m src.training.trainer --data path/to/data.yaml --epochs 30
```

## 📊 Categorias Detectadas

| Categoria | Exemplos |
|-----------|----------|
| Compute | EC2, Lambda, EKS, Fargate |
| Database | RDS, DynamoDB, Aurora, Redis |
| Storage | S3, EBS, EFS, Glacier |
| Network | VPC, CloudFront, Route 53 |
| Security | IAM, WAF, KMS, Cognito |
| API Gateway | API Gateway, AppSync |
| Messaging | SQS, SNS, EventBridge |
| Monitoring | CloudWatch, CloudTrail |
| ML/AI | SageMaker, Rekognition |
| DevOps | CodePipeline, CloudFormation |

##  Licença

MIT