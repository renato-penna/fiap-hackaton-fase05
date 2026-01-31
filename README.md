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
├── models/
│   ├── best.pt                # Modelo YOLO treinado
│   └── yolo11n.pt             # Modelo base YOLO
├── src/
│   ├── app.py                 # Aplicação Streamlit
│   ├── stride_engine.py       # Motor de análise STRIDE
│   ├── train_model.py         # Script de treino local
│   ├── train_colab.ipynb      # Notebook para Google Colab
│   └── analyze_dataset.py     # Análise do dataset
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

1. Faça upload do dataset para o Google Drive em `/colab/cloud-arch-security-mvp/dataset/`
2. Abra o notebook `src/train_colab.ipynb` no Colab
3. Execute todas as células
4. O modelo treinado será salvo em `weights_backup/best_optimized.pt`
5. Copie o modelo para `models/best.pt` localmente

### Opção 2: Treino Local (GPU necessária)

```bash
cd src
python train_model.py
```

**Requisitos GPU Local:**
- NVIDIA GPU com CUDA 11.8+
- Mínimo 4GB VRAM (recomendado 8GB+)
- NVIDIA RTX 2060 ou superior

## 📊 Categorias Detectadas

O modelo foi otimizado para detectar as seguintes categorias de componentes:

| Categoria | Componentes Exemplo |
|-----------|---------------------|
| **compute** | EC2, Lambda, EKS, Containers |
| **database** | RDS, DynamoDB, Aurora, Redis |
| **storage** | S3, EBS, Glacier, File Share |
| **network** | VPC, Gateway, Subnet, Endpoint |
| **security** | WAF, Firewall, Shield, GuardDuty |
| **api_gateway** | API Gateway, ALB, CloudFront |
| **messaging** | SQS, SNS, EventBridge |
| **monitoring** | CloudWatch, CloudTrail, X-Ray |
| **identity** | IAM, Cognito, AAD |
| **ml_ai** | SageMaker, Rekognition, Lex |
| **devops** | CodePipeline, Jenkins, GitHub |
| **serverless** | Lambda, Fargate, Step Functions |
| **groups** | VPC, Region, Availability Zone |

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
