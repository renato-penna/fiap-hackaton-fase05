"""
STRIDE Engine - Motor de Análise de Vulnerabilidades para Arquiteturas Cloud
==============================================================================

Este módulo implementa a metodologia STRIDE para análise de ameaças em componentes
de infraestrutura de nuvem (AWS/Azure) detectados visualmente pelo modelo YOLO.

STRIDE:
- S: Spoofing (Falsificação de Identidade)
- T: Tampering (Adulteração de Dados)
- R: Repudiation (Repúdio)
- I: Information Disclosure (Vazamento de Informações)
- D: Denial of Service (Negação de Serviço)
- E: Elevation of Privilege (Elevação de Privilégio)

Autor: MVP Pós-Graduação FIAP
Data: 2024-2026
"""

from typing import Dict, List, Optional, Any


class StrideEngine:
    """
    Motor de análise STRIDE para componentes de arquitetura cloud.
    
    Suporta as categorias simplificadas do modelo YOLO:
    - compute, database, storage, network, security, api_gateway,
    - messaging, monitoring, identity, ml_ai, devops, serverless, groups, other
    """
    
    # Mapeamento de categorias simplificadas para métodos de análise
    CATEGORY_ANALYZERS = {
        'compute': '_analyze_compute',
        'database': '_analyze_database',
        'storage': '_analyze_storage',
        'network': '_analyze_network',
        'security': '_analyze_security',
        'api_gateway': '_analyze_api_gateway',
        'messaging': '_analyze_messaging',
        'monitoring': '_analyze_monitoring',
        'identity': '_analyze_identity',
        'ml_ai': '_analyze_ml_ai',
        'devops': '_analyze_devops',
        'serverless': '_analyze_serverless',
        'groups': '_analyze_groups',
        'other': '_analyze_other',
    }
    
    # Mapeamento de componentes individuais (legado + novos)
    COMPONENT_TO_CATEGORY = {
        # Computação
        'EC2': 'compute', 'Lambda': 'serverless', 'EKS': 'compute',
        'Fargate': 'serverless', 'Container': 'compute', 'Server': 'compute',
        'Vm Scaleset': 'compute', 'Virtual Machine': 'compute',
        'Elastic Container Service': 'compute', 'App gateway': 'api_gateway',
        
        # Bancos de Dados
        'RDS': 'database', 'DynamoDB': 'database', 'Aurora': 'database',
        'DocumentDB': 'database', 'ElastiCache': 'database', 'Redis': 'database',
        'MySQL': 'database', 'PostgreSQL': 'database', 'Neptune': 'database',
        'Redshift': 'database', 'Table': 'database', 'DB': 'database',
        'Oracle DB': 'database', 'Mongo DB': 'database', 'Cosmos DB': 'database',
        'Memcached': 'database',
        
        # Armazenamento
        'S3': 'storage', 'EBS': 'storage', 'EFS': 'storage',
        'Glacier': 'storage', 'Storage Gateway': 'storage', 'File share': 'storage',
        'Snowball': 'storage', 'Backup': 'storage', 'DataSync': 'storage',
        'Blob Storage': 'storage',
        
        # Rede
        'VPC Router': 'network', 'Internet Gateway': 'network',
        'NAT Gateway': 'network', 'Transit Gateway': 'network',
        'Direct Connect': 'network', 'Private Link': 'network',
        'V-net': 'network', 'Private Subnet': 'network', 'Public Subnet': 'network',
        'Availability Zone': 'groups', 'Region': 'groups',
        'Endpoint': 'network', 'Network Firewall': 'security',
        'Customer Gateway': 'network', 'VP Gateway': 'network',
        
        # Segurança
        'IAM': 'identity', 'IAM Role': 'identity', 'Cognito': 'identity',
        'WAF': 'security', 'Firewall': 'security', 'Shield': 'security',
        'GuardDuty': 'security', 'Inspector Agent': 'security',
        'Security Hub': 'security', 'Secrets Manager': 'security',
        'Key Management Service': 'security', 'CloudHSM': 'security',
        'Certificate Manager': 'security', 'Macie': 'security',
        'Detective': 'security', 'Key vault': 'security',
        'Security Group': 'security', 'Firewall Manager': 'security',
        'Config': 'monitoring', 'Trusted Advisor': 'monitoring',
        
        # API Gateway e CDN
        'API-Gateway': 'api_gateway', 'Appsync': 'api_gateway',
        'ALB': 'api_gateway', 'ELB': 'api_gateway', 'Cloudfront': 'api_gateway',
        'CDN': 'api_gateway', 'Route53': 'network', 'Cloud Map': 'network',
        'Distribution': 'api_gateway', 'Edge Location': 'api_gateway',
        
        # Mensageria
        'SQS': 'messaging', 'SNS': 'messaging', 'EventBridge': 'messaging',
        'Event Bus': 'messaging', 'MQ': 'messaging',
        'Kinesis Data Streams': 'messaging', 'Step Function': 'serverless',
        
        # Monitoramento
        'Cloud Watch': 'monitoring', 'CloudWatch Alarm': 'monitoring',
        'Cloud Trail': 'monitoring', 'X-Ray': 'monitoring',
        'Azure monitor': 'monitoring', 'Grafana': 'monitoring',
        'Prometheus': 'monitoring', 'Flow logs': 'monitoring',
        
        # Identidade
        'AAD': 'identity', 'Active Directory Service': 'identity',
        'Sign-On': 'identity', 'Users': 'identity', 'Client': 'other',
        
        # ML/AI
        'Sagemaker': 'ml_ai', 'Rekognition': 'ml_ai', 'Comprehend': 'ml_ai',
        'Lex': 'ml_ai', 'Textract': 'ml_ai', 'Transcribe': 'ml_ai',
        'Translate': 'ml_ai', 'Machine Learning': 'ml_ai', 'Notebook': 'ml_ai',
        
        # DevOps
        'CodePipeline': 'devops', 'CodeBuild': 'devops', 'CodeCommit': 'devops',
        'CodeDeploy': 'devops', 'Jenkins': 'devops', 'Github': 'devops',
        'Git': 'devops', 'Docker Image': 'devops', 'Image Builder': 'devops',
        'CloudFormation Stack': 'devops', 'Terraform': 'devops',
        'Deploy Stage': 'devops', 'Build Environment': 'devops',
        
        # Serverless
        'Amplify': 'serverless', 'AppFlow': 'serverless',
        
        # Grupos
        'groups': 'groups',
    }
    
    def __init__(self):
        """Inicializa o motor STRIDE com base de conhecimento."""
        self._build_knowledge_base()
    
    def _build_knowledge_base(self):
        """Constrói a base de conhecimento de riscos por categoria."""
        self.knowledge_base = {}
        for component, category in self.COMPONENT_TO_CATEGORY.items():
            self.knowledge_base[component] = category
    
    def analyze(self, component_name: str) -> Optional[Dict[str, Any]]:
        """
        Analisa um componente e retorna os riscos STRIDE associados.
        
        Args:
            component_name: Nome da classe detectada pelo modelo YOLO
            
        Returns:
            Dicionário com análise STRIDE ou None se não reconhecido
        """
        return self.analyze_component(component_name)
    
    def analyze_component(self, component_name: str) -> Optional[Dict[str, Any]]:
        """
        Analisa um componente específico ou categoria e retorna riscos STRIDE.
        
        Args:
            component_name: Nome do componente (ex: 'EC2', 'S3') ou categoria (ex: 'compute', 'storage')
            
        Returns:
            Dicionário com:
            - component: nome do componente
            - category: categoria de segurança
            - stride/risks: lista de ameaças com tipo, detalhe e mitigação
            - note: observações adicionais (opcional)
        """
        # Verifica se é uma categoria direta (modelo simplificado)
        if component_name in self.CATEGORY_ANALYZERS:
            analyzer_method = getattr(self, self.CATEGORY_ANALYZERS[component_name])
            return analyzer_method(component_name)
        
        # Busca categoria pelo nome do componente (modelo original)
        category = self.knowledge_base.get(component_name)
        if category and category in self.CATEGORY_ANALYZERS:
            analyzer_method = getattr(self, self.CATEGORY_ANALYZERS[category])
            result = analyzer_method(component_name)
            # Sobrescreve o nome do componente específico
            result['component'] = component_name
            return result
        
        # Componente não reconhecido
        return None
    
    def analyze_architecture(self, components: List[str]) -> Dict[str, Any]:
        """
        Analisa uma arquitetura completa (múltiplos componentes).
        
        Args:
            components: Lista de componentes detectados
            
        Returns:
            Relatório consolidado com análises individuais e score de risco
        """
        analyses = []
        security_controls = []
        risk_count = 0
        
        for component in components:
            analysis = self.analyze_component(component)
            if analysis:
                analyses.append(analysis)
                
                # Conta riscos
                risks = analysis.get('risks') or analysis.get('stride') or []
                risk_count += len(risks)
                
                # Identifica controles de segurança presentes
                if analysis.get('category') == 'Security Control':
                    security_controls.append(component)
        
        # Calcula score de risco (simplificado)
        security_bonus = len(security_controls) * 0.1
        risk_score = max(0, min(1, (risk_count / max(len(components), 1)) - security_bonus))
        
        return {
            'total_components': len(components),
            'analyzed_components': len(analyses),
            'total_risks': risk_count,
            'security_controls': security_controls,
            'risk_score': round(risk_score, 2),
            'risk_level': self._get_risk_level(risk_score),
            'analyses': analyses
        }
    
    def _get_risk_level(self, score: float) -> str:
        """Converte score numérico em nível de risco textual."""
        if score < 0.3:
            return 'LOW'
        elif score < 0.6:
            return 'MEDIUM'
        elif score < 0.8:
            return 'HIGH'
        return 'CRITICAL'
    
    # =====================================================================
    # ANALISADORES POR CATEGORIA (STRIDE)
    # =====================================================================
    
    def _analyze_compute(self, component: str) -> Dict[str, Any]:
        """Análise STRIDE para recursos de computação."""
        return {
            "component": component,
            "category": "Compute",
            "description": "Recursos de processamento (VMs, containers, instâncias)",
            "risks": [
                {
                    "type": "Spoofing",
                    "threat": "S - Falsificação de Identidade",
                    "detail": "Acesso não autorizado via credenciais vazadas ou chaves SSH expostas.",
                    "mitigation": "Usar AWS Session Manager ou Azure Bastion. Desabilitar acesso SSH direto.",
                    "severity": "HIGH"
                },
                {
                    "type": "Tampering",
                    "threat": "T - Adulteração",
                    "detail": "Modificação não autorizada de binários ou configurações.",
                    "mitigation": "Implementar File Integrity Monitoring (FIM). Usar imagens imutáveis.",
                    "severity": "MEDIUM"
                },
                {
                    "type": "Elevation of Privilege",
                    "threat": "E - Elevação de Privilégio",
                    "detail": f"Instância {component} com IAM Roles permissivas demais.",
                    "mitigation": "Aplicar princípio do privilégio mínimo. Usar IAM Access Analyzer.",
                    "severity": "HIGH"
                },
                {
                    "type": "Denial of Service",
                    "threat": "D - Negação de Serviço",
                    "detail": "Esgotamento de recursos (CPU, memória, disco).",
                    "mitigation": "Configurar Auto Scaling, limites de recursos e alarmes CloudWatch.",
                    "severity": "MEDIUM"
                }
            ]
        }
    
    def _analyze_database(self, component: str) -> Dict[str, Any]:
        """Análise STRIDE para bancos de dados."""
        return {
            "component": component,
            "category": "Database",
            "description": "Sistemas de armazenamento de dados estruturados",
            "risks": [
                {
                    "type": "Information Disclosure",
                    "threat": "I - Vazamento de Informações",
                    "detail": "Dados sensíveis em repouso podem ser acessados se o armazenamento for comprometido.",
                    "mitigation": "Habilitar criptografia em repouso (TDE/KMS). Usar Customer Managed Keys.",
                    "severity": "CRITICAL"
                },
                {
                    "type": "Tampering",
                    "threat": "T - Adulteração",
                    "detail": "SQL Injection ou modificação direta de dados via aplicação comprometida.",
                    "mitigation": "Usar Prepared Statements/ORM. Habilitar audit logs e backups automáticos.",
                    "severity": "HIGH"
                },
                {
                    "type": "Spoofing",
                    "threat": "S - Falsificação de Identidade",
                    "detail": "Conexões não autenticadas ao banco de dados.",
                    "mitigation": "Habilitar SSL/TLS obrigatório. Usar IAM Database Authentication quando disponível.",
                    "severity": "HIGH"
                },
                {
                    "type": "Denial of Service",
                    "threat": "D - Negação de Serviço",
                    "detail": "Queries pesadas ou conexões excessivas esgotando recursos.",
                    "mitigation": "Configurar connection pooling, query timeout e read replicas.",
                    "severity": "MEDIUM"
                }
            ]
        }
    
    def _analyze_storage(self, component: str) -> Dict[str, Any]:
        """Análise STRIDE para armazenamento de objetos/arquivos."""
        return {
            "component": component,
            "category": "Storage",
            "description": "Armazenamento de objetos, arquivos e backups",
            "risks": [
                {
                    "type": "Information Disclosure",
                    "threat": "I - Vazamento de Informações",
                    "detail": f"Bucket/Storage {component} pode estar configurado como público inadvertidamente.",
                    "mitigation": "Habilitar 'Block Public Access'. Usar bucket policies restritivas. Auditar com Access Analyzer.",
                    "severity": "CRITICAL"
                },
                {
                    "type": "Tampering",
                    "threat": "T - Adulteração",
                    "detail": "Dados podem ser modificados ou deletados sem proteção.",
                    "mitigation": "Habilitar Versionamento, MFA Delete e Object Lock para dados críticos.",
                    "severity": "HIGH"
                },
                {
                    "type": "Repudiation",
                    "threat": "R - Repúdio",
                    "detail": "Falta de logs de acesso dificulta auditoria e investigação.",
                    "mitigation": "Habilitar Server Access Logging e CloudTrail Data Events.",
                    "severity": "MEDIUM"
                }
            ]
        }
    
    def _analyze_network(self, component: str) -> Dict[str, Any]:
        """Análise STRIDE para componentes de rede."""
        return {
            "component": component,
            "category": "Network",
            "description": "Componentes de infraestrutura de rede",
            "risks": [
                {
                    "type": "Information Disclosure",
                    "threat": "I - Vazamento de Informações",
                    "detail": "Tráfego de rede não criptografado pode ser interceptado.",
                    "mitigation": "Forçar TLS 1.2+ em todo tráfego. Usar VPN/PrivateLink para conexões sensíveis.",
                    "severity": "HIGH"
                },
                {
                    "type": "Spoofing",
                    "threat": "S - Falsificação de Identidade",
                    "detail": "Ataques de ARP spoofing ou DNS poisoning na rede.",
                    "mitigation": "Usar VPC Flow Logs. Habilitar DNS firewall. Segmentar redes adequadamente.",
                    "severity": "MEDIUM"
                },
                {
                    "type": "Denial of Service",
                    "threat": "D - Negação de Serviço",
                    "detail": "Ataques DDoS podem saturar a largura de banda.",
                    "mitigation": "Usar AWS Shield, CloudFront e WAF. Configurar rate limiting.",
                    "severity": "HIGH"
                }
            ]
        }
    
    def _analyze_security(self, component: str) -> Dict[str, Any]:
        """Análise para controles de segurança (WAF, Firewall, etc.)."""
        return {
            "component": component,
            "category": "Security Control",
            "description": "Controle de segurança ativo na arquitetura",
            "note": "✅ Componente de proteção detectado! Verifique se as regras estão atualizadas.",
            "risks": [
                {
                    "type": "Misconfiguration",
                    "threat": "Configuração Incorreta",
                    "detail": "Regras desatualizadas ou permissivas podem anular a proteção.",
                    "mitigation": "Revisar regras regularmente. Usar managed rules quando disponível.",
                    "severity": "MEDIUM"
                }
            ]
        }
    
    def _analyze_api_gateway(self, component: str) -> Dict[str, Any]:
        """Análise STRIDE para API Gateways e Load Balancers."""
        return {
            "component": component,
            "category": "API Gateway",
            "description": "Ponto de entrada para APIs e serviços",
            "risks": [
                {
                    "type": "Denial of Service",
                    "threat": "D - Negação de Serviço",
                    "detail": "Sobrecarga de requisições na API sem controle de taxa.",
                    "mitigation": "Implementar throttling, rate limiting e usage plans.",
                    "severity": "HIGH"
                },
                {
                    "type": "Spoofing",
                    "threat": "S - Falsificação de Identidade",
                    "detail": "APIs públicas sem autenticação adequada.",
                    "mitigation": "Usar Cognito/OAuth2 Authorizers. Implementar mTLS para APIs internas.",
                    "severity": "CRITICAL"
                },
                {
                    "type": "Information Disclosure",
                    "threat": "I - Vazamento de Informações",
                    "detail": "Logs de API podem expor dados sensíveis.",
                    "mitigation": "Mascarar dados sensíveis em logs. Usar encryption at rest nos logs.",
                    "severity": "MEDIUM"
                },
                {
                    "type": "Tampering",
                    "threat": "T - Adulteração",
                    "detail": "Requisições podem ser manipuladas em trânsito.",
                    "mitigation": "Forçar HTTPS. Validar input rigorosamente. Usar request signing.",
                    "severity": "HIGH"
                }
            ]
        }
    
    def _analyze_messaging(self, component: str) -> Dict[str, Any]:
        """Análise STRIDE para serviços de mensageria."""
        return {
            "component": component,
            "category": "Messaging",
            "description": "Serviços de filas e eventos assíncronos",
            "risks": [
                {
                    "type": "Information Disclosure",
                    "threat": "I - Vazamento de Informações",
                    "detail": "Mensagens em filas podem conter dados sensíveis não criptografados.",
                    "mitigation": "Habilitar SSE-KMS em filas/tópicos. Criptografar payload em nível de aplicação.",
                    "severity": "HIGH"
                },
                {
                    "type": "Tampering",
                    "threat": "T - Adulteração",
                    "detail": "Mensagens podem ser injetadas ou modificadas por atacantes.",
                    "mitigation": "Usar Dead Letter Queues. Validar schema das mensagens. Implementar signing.",
                    "severity": "MEDIUM"
                },
                {
                    "type": "Denial of Service",
                    "threat": "D - Negação de Serviço",
                    "detail": "Poison messages podem bloquear consumers.",
                    "mitigation": "Configurar DLQ, visibility timeout e max receive count adequados.",
                    "severity": "MEDIUM"
                }
            ]
        }
    
    def _analyze_monitoring(self, component: str) -> Dict[str, Any]:
        """Análise para serviços de monitoramento e logging."""
        return {
            "component": component,
            "category": "Monitoring",
            "description": "Serviço de monitoramento e observabilidade",
            "note": "✅ Componente de observabilidade detectado! Essencial para detecção de incidentes.",
            "risks": [
                {
                    "type": "Information Disclosure",
                    "threat": "I - Vazamento de Informações",
                    "detail": "Logs podem inadvertidamente registrar dados sensíveis (senhas, tokens).",
                    "mitigation": "Implementar log redaction. Criptografar logs com CMK. Restringir acesso.",
                    "severity": "MEDIUM"
                },
                {
                    "type": "Tampering",
                    "threat": "T - Adulteração",
                    "detail": "Atacantes podem tentar apagar logs para cobrir rastros.",
                    "mitigation": "Usar S3 Object Lock para logs. Enviar para conta separada de auditoria.",
                    "severity": "HIGH"
                }
            ]
        }
    
    def _analyze_identity(self, component: str) -> Dict[str, Any]:
        """Análise STRIDE para serviços de identidade."""
        return {
            "component": component,
            "category": "Identity",
            "description": "Gerenciamento de identidades e acessos",
            "risks": [
                {
                    "type": "Elevation of Privilege",
                    "threat": "E - Elevação de Privilégio",
                    "detail": "Políticas IAM permissivas demais podem permitir escalação de privilégios.",
                    "mitigation": "Usar IAM Access Analyzer. Aplicar least privilege. Revisar regularmente.",
                    "severity": "CRITICAL"
                },
                {
                    "type": "Spoofing",
                    "threat": "S - Falsificação de Identidade",
                    "detail": "Credenciais de longa duração podem ser comprometidas.",
                    "mitigation": "Habilitar MFA obrigatório. Usar roles temporárias. Rotacionar chaves.",
                    "severity": "CRITICAL"
                },
                {
                    "type": "Repudiation",
                    "threat": "R - Repúdio",
                    "detail": "Ações administrativas sem trilha de auditoria.",
                    "mitigation": "Habilitar CloudTrail em todas as regiões. Usar Organization Trail.",
                    "severity": "HIGH"
                }
            ]
        }
    
    def _analyze_ml_ai(self, component: str) -> Dict[str, Any]:
        """Análise para serviços de Machine Learning e AI."""
        return {
            "component": component,
            "category": "ML/AI",
            "description": "Serviços de inteligência artificial e machine learning",
            "risks": [
                {
                    "type": "Information Disclosure",
                    "threat": "I - Vazamento de Informações",
                    "detail": "Dados de treinamento podem conter informações sensíveis.",
                    "mitigation": "Anonimizar dados de treino. Usar VPC endpoints. Criptografar modelos.",
                    "severity": "HIGH"
                },
                {
                    "type": "Tampering",
                    "threat": "T - Adulteração",
                    "detail": "Ataques de data poisoning podem comprometer a integridade do modelo.",
                    "mitigation": "Validar fontes de dados. Versionar modelos. Monitorar drift.",
                    "severity": "MEDIUM"
                }
            ]
        }
    
    def _analyze_devops(self, component: str) -> Dict[str, Any]:
        """Análise para ferramentas de CI/CD e DevOps."""
        return {
            "component": component,
            "category": "DevOps",
            "description": "Ferramentas de CI/CD e automação",
            "risks": [
                {
                    "type": "Elevation of Privilege",
                    "threat": "E - Elevação de Privilégio",
                    "detail": "Pipelines CI/CD geralmente têm permissões elevadas para deploy.",
                    "mitigation": "Usar roles específicas por stage. Requerer aprovação para produção.",
                    "severity": "CRITICAL"
                },
                {
                    "type": "Tampering",
                    "threat": "T - Adulteração",
                    "detail": "Código malicioso pode ser injetado no pipeline.",
                    "mitigation": "Habilitar branch protection. Requerer code review. Assinar commits.",
                    "severity": "HIGH"
                },
                {
                    "type": "Information Disclosure",
                    "threat": "I - Vazamento de Informações",
                    "detail": "Secrets podem ser expostos em logs de build.",
                    "mitigation": "Usar Secrets Manager. Nunca hardcode secrets. Mascarar em logs.",
                    "severity": "HIGH"
                }
            ]
        }
    
    def _analyze_serverless(self, component: str) -> Dict[str, Any]:
        """Análise para serviços serverless."""
        return {
            "component": component,
            "category": "Serverless",
            "description": "Funções e serviços serverless",
            "risks": [
                {
                    "type": "Elevation of Privilege",
                    "threat": "E - Elevação de Privilégio",
                    "detail": "Funções Lambda com IAM Role permissiva.",
                    "mitigation": "Aplicar least privilege por função. Usar Resource-based policies.",
                    "severity": "HIGH"
                },
                {
                    "type": "Denial of Service",
                    "threat": "D - Negação de Serviço",
                    "detail": "Execução recursiva ou loop infinito pode esgotar concurrency.",
                    "mitigation": "Configurar reserved concurrency. Definir timeout adequado.",
                    "severity": "MEDIUM"
                },
                {
                    "type": "Information Disclosure",
                    "threat": "I - Vazamento de Informações",
                    "detail": "Environment variables podem expor secrets.",
                    "mitigation": "Usar Secrets Manager/Parameter Store. Criptografar variáveis com CMK.",
                    "severity": "HIGH"
                }
            ]
        }
    
    def _analyze_groups(self, component: str) -> Dict[str, Any]:
        """Análise para grupos/boundaries (VPC, Regions, AZs)."""
        return {
            "component": component,
            "category": "Trust Boundary",
            "description": "Agrupamento lógico ou boundary de confiança",
            "risks": [
                {
                    "type": "Elevation of Privilege",
                    "threat": "E - Elevação de Privilégio",
                    "detail": "Mistura de recursos com diferentes níveis de confiança no mesmo boundary.",
                    "mitigation": "Segmentar recursos públicos e privados em subnets/VPCs separadas.",
                    "severity": "HIGH"
                },
                {
                    "type": "Information Disclosure",
                    "threat": "I - Vazamento de Informações",
                    "detail": "Security Groups herdados podem permitir acesso não intencional.",
                    "mitigation": "Auditar Security Groups. Usar VPC Flow Logs. Aplicar segmentação.",
                    "severity": "MEDIUM"
                }
            ],
            "note": "⚠️ Boundary detectado. Verifique se há segregação adequada entre níveis de confiança."
        }
    
    def _analyze_other(self, component: str) -> Dict[str, Any]:
        """Análise genérica para componentes não categorizados."""
        return {
            "component": component,
            "category": "Uncategorized",
            "description": "Componente não categorizado",
            "note": f"ℹ️ O componente '{component}' foi detectado mas não possui regras STRIDE específicas.",
            "risks": [
                {
                    "type": "Unknown",
                    "threat": "Análise Manual Requerida",
                    "detail": "Este componente requer análise de segurança manual.",
                    "mitigation": "Consulte a documentação de segurança do serviço específico.",
                    "severity": "LOW"
                }
            ]
        }