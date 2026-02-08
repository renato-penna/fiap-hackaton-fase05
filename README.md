# 🛡️ Cloud Architecture Security Analyzer - MVP

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![YOLO v11](https://img.shields.io/badge/YOLO-v11-green.svg)](https://github.com/ultralytics/ultralytics)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-red.svg)](https://streamlit.io/)

## 📋 Sobre o Projeto

MVP desenvolvido para a **Pós-Graduação FIAP** que utiliza **detecção visual com Deep Learning** para analisar diagramas de arquitetura de software (AWS/Azure) e identificar vulnerabilidades de segurança usando a metodologia **STRIDE**.

### Funcionalidades

- 🔍 **Detecção Visual**: Identifica componentes de infraestrutura cloud em diagramas
- 🛡️ **Análise STRIDE**: Gera relatório de vulnerabilidades e mitigações
- 📊 **Score de Risco**: Classifica o nível de risco da arquitetura
- 📥 **Exportação**: Relatórios em JSON para documentação

## 🏗️ Arquitetura

```
cloud-arch-security-mvp/
├── dataset/                    # Dataset YOLO com anotações
│   ├── data.yaml              # Configuração das classes
│   ├── train/images/labels/   # Conjunto de treino
│   ├── valid/images/labels/   # Conjunto de validação
│   └── test/images/labels/    # Conjunto de teste
├── diagram/                    # Diagramas customizados para anotação
│   ├── imagem01.png           # Diagrama customizado
│   └── imagem01.json          # Anotações LabelMe (JSON)
├── kaggle_dataset_cache/       # Cache do dataset Kaggle original
│   └── kaggle_dataset_cache.zip
├── models/
│   ├── best.pt                # Modelo YOLO treinado
│   └── yolo11n.pt             # Modelo base YOLO
├── src/
│   ├── app.py                 # Aplicação Streamlit
│   ├── stride_engine.py       # Motor de análise STRIDE
│   ├── train_model.py         # Script de treino local
│   ├── train_colab.ipynb      # Notebook para Google Colab
│   └── analyze_dataset.py     # Análise do dataset (evolução)
├── prepare_dataset.py          # Prepara dataset: Kaggle + anotações customizadas
└── requirements.txt           # Dependências Python
```

## 🚀 Instalação

### 1. Clone o repositório

```bash
git clone https://github.com/seu-usuario/cloud-arch-security-mvp.git
cd cloud-arch-security-mvp
```

### 2. Crie um ambiente virtual

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

### 3. Instale as dependências

```bash
pip install -r requirements.txt
```

### 4. Execute a aplicação

```bash
cd src
streamlit run app.py
```

## 🎓 Treinamento do Modelo

### Opção 1: Google Colab (Recomendado)

1. **Prepare o dataset localmente:**
   ```bash
   python prepare_dataset.py
   ```
   Isso combina o dataset Kaggle + suas anotações customizadas (pasta `diagram/`)

2. **Faça upload** do arquivo `dataset_ready.zip` para o Google Drive em:
   ```
   My Drive/colab/cloud-arch-security-mvp/kaggle_dataset_cache/dataset_ready.zip
   ```

3. **Abra** o notebook `src/train_colab.ipynb` no Google Colab

4. **Execute** todas as células - o treinamento suporta **checkpoint/resume**

5. **Baixe** o modelo treinado de `weights_backup/best_kaggle.pt` e copie para `models/best.pt`

### Opção 2: Treino Local (GPU necessária)

```bash
cd src
python train_model.py
```

**Requisitos GPU Local:**
- NVIDIA GPU com CUDA 11.8+
- Mínimo 4GB VRAM (recomendado 8GB+)
- NVIDIA RTX 2060 ou superior

## 📊 Categorias Detectadas (14 Categorias STRIDE + Other)

O modelo foi treinado para detectar **15 categorias** de componentes cloud (AWS/Azure/GCP):

| Categoria | Componentes Exemplo |
|-----------|---------------------|
| **compute** | EC2, Lambda, EKS, Fargate, VM, SEI, SIP |
| **database** | RDS, DynamoDB, Aurora, Redis, Cosmos DB |
| **storage** | S3, EBS, EFS, Glacier, Blob Storage |
| **network** | VPC, Load Balancer, CloudFront, Route 53 |
| **security** | IAM, WAF, KMS, Cognito, GuardDuty |
| **api_gateway** | API Gateway, AppSync, Apigee |
| **messaging** | SQS, SNS, SES, EventBridge, Kinesis |
| **monitoring** | CloudWatch, CloudTrail, X-Ray |
| **identity** | User, Client, Active Directory |
| **ml_ai** | SageMaker, Rekognition, Vertex AI |
| **devops** | CodePipeline, ECR, CloudFormation |
| **serverless** | Lambda, Step Functions, Cloud Functions |
| **analytics** | Athena, Glue, BigQuery, Redshift |
| **other** | Componentes não mapeados |

## 🔐 Metodologia STRIDE

O sistema analisa cada componente detectado usando a metodologia STRIDE:

- **S**poofing: Falsificação de identidade
- **T**ampering: Adulteração de dados
- **R**epudiation: Repúdio de ações
- **I**nformation Disclosure: Vazamento de informações
- **D**enial of Service: Negação de serviço
- **E**levation of Privilege: Escalação de privilégios

## 📈 Métricas do Modelo

Após o treinamento otimizado:

| Métrica | Valor |
|---------|-------|
| mAP50 | ~0.75+ |
| mAP50-95 | ~0.55+ |
| Precisão | ~0.70+ |
| Recall | ~0.65+ |

## 🛠️ Configurações

### Threshold de Confiança

Ajuste no sidebar da aplicação:
- **Padrão**: 0.35 (recomendado para diagramas complexos)
- **Alto**: 0.50+ (menos falsos positivos, pode perder detecções)
- **Baixo**: 0.20 (mais detecções, mais falsos positivos)

## 📝 Licença

Este projeto é desenvolvido para fins acadêmicos como parte da Pós-Graduação FIAP.

## 👥 Contribuidores

- Desenvolvido como MVP para Pós-Graduação FIAP - Módulo 05

## 📚 Referências

- [STRIDE Threat Modeling](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [Ultralytics YOLOv11](https://github.com/ultralytics/ultralytics)
- [AWS Architecture Icons](https://aws.amazon.com/architecture/icons/)
- [Azure Architecture Icons](https://docs.microsoft.com/en-us/azure/architecture/icons/)
