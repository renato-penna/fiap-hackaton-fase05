"""Base de conhecimento STRIDE para componentes cloud."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ThreatRisk:
    """Representa um risco STRIDE individual."""

    threat_type: str
    threat_label: str
    detail: str
    mitigation: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW


@dataclass(frozen=True)
class ComponentAnalysis:
    """Resultado da análise STRIDE de um componente."""

    component: str
    category: str
    element_type: str
    stride_summary: str
    description: str
    risks: list[ThreatRisk]

    @property
    def risk_count(self) -> int:
        return len(self.risks)

    @property
    def max_severity(self) -> str:
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        if not self.risks:
            return "LOW"
        return max(self.risks, key=lambda r: severity_order.get(r.severity, 0)).severity

    def to_dict(self) -> dict:
        return {
            "component": self.component,
            "category": self.category,
            "element_type": self.element_type,
            "stride_summary": self.stride_summary,
            "description": self.description,
            "risks": [
                {
                    "type": r.threat_type,
                    "threat": r.threat_label,
                    "detail": r.detail,
                    "mitigation": r.mitigation,
                    "severity": r.severity,
                }
                for r in self.risks
            ],
        }


# ---------------------------------------------------------------------------
# Threat definitions per category
# ---------------------------------------------------------------------------

COMPUTE_THREATS = [
    ThreatRisk(
        threat_type="Spoofing",
        threat_label="S - Falsificação de Identidade",
        detail="Instâncias podem ser clonadas ou falsificadas por atacantes.",
        mitigation="Habilitar IMDSv2, usar security groups restritos e IAM roles.",
        severity="HIGH",
    ),
    ThreatRisk(
        threat_type="Tampering",
        threat_label="T - Adulteração",
        detail="Modificação não autorizada de configurações ou dados da instância.",
        mitigation="Habilitar CloudTrail, usar AMIs verificadas e integrity monitoring.",
        severity="HIGH",
    ),
    ThreatRisk(
        threat_type="Elevation of Privilege",
        threat_label="E - Elevação de Privilégio",
        detail="Exploração de vulnerabilidades para ganhar privilégios root.",
        mitigation="Aplicar patches regularmente, usar least privilege em IAM roles.",
        severity="CRITICAL",
    ),
]

DATABASE_THREATS = [
    ThreatRisk(
        threat_type="Information Disclosure",
        threat_label="I - Vazamento de Informações",
        detail="Dados sensíveis podem ser expostos via queries ou backups não criptografados.",
        mitigation="Habilitar encryption at-rest e in-transit, usar VPC endpoints.",
        severity="CRITICAL",
    ),
    ThreatRisk(
        threat_type="Tampering",
        threat_label="T - Adulteração",
        detail="Modificação não autorizada de registros do banco.",
        mitigation="Habilitar audit logging, usar IAM authentication e parameter groups seguros.",
        severity="HIGH",
    ),
    ThreatRisk(
        threat_type="Denial of Service",
        threat_label="D - Negação de Serviço",
        detail="Consultas pesadas ou connection flooding podem causar indisponibilidade.",
        mitigation="Configurar connection pooling, query timeout e read replicas.",
        severity="MEDIUM",
    ),
]

STORAGE_THREATS = [
    ThreatRisk(
        threat_type="Information Disclosure",
        threat_label="I - Vazamento de Informações",
        detail="Buckets/blobs públicos podem expor dados sensíveis.",
        mitigation="Bloquear acesso público, habilitar encryption e bucket policies restritas.",
        severity="CRITICAL",
    ),
    ThreatRisk(
        threat_type="Tampering",
        threat_label="T - Adulteração",
        detail="Objetos podem ser modificados ou deletados sem autorização.",
        mitigation="Habilitar versioning, MFA delete e Object Lock.",
        severity="HIGH",
    ),
    ThreatRisk(
        threat_type="Repudiation",
        threat_label="R - Repúdio",
        detail="Ações em objetos sem trilha de auditoria.",
        mitigation="Habilitar S3 access logging e CloudTrail data events.",
        severity="MEDIUM",
    ),
]

NETWORK_THREATS = [
    ThreatRisk(
        threat_type="Spoofing",
        threat_label="S - Falsificação de Identidade",
        detail="Tráfego de rede pode ser spoofed para acessar recursos internos.",
        mitigation="Usar NACLs, security groups e VPN/Direct Connect para acesso.",
        severity="HIGH",
    ),
    ThreatRisk(
        threat_type="Information Disclosure",
        threat_label="I - Vazamento de Informações",
        detail="Tráfego não criptografado pode ser interceptado.",
        mitigation="Usar TLS em trânsito, VPC Flow Logs e endpoints privados.",
        severity="HIGH",
    ),
    ThreatRisk(
        threat_type="Denial of Service",
        threat_label="D - Negação de Serviço",
        detail="Ataques DDoS podem tornar o serviço indisponível.",
        mitigation="Usar AWS Shield, WAF e CloudFront para mitigação de DDoS.",
        severity="HIGH",
    ),
]

SECURITY_THREATS = [
    ThreatRisk(
        threat_type="Elevation of Privilege",
        threat_label="E - Elevação de Privilégio",
        detail="Políticas IAM permissivas podem permitir escalonamento de privilégios.",
        mitigation="Aplicar least privilege, usar IAM Access Analyzer e SCPs.",
        severity="CRITICAL",
    ),
    ThreatRisk(
        threat_type="Spoofing",
        threat_label="S - Falsificação de Identidade",
        detail="Credenciais comprometidas podem ser usadas para impersonação.",
        mitigation="Habilitar MFA, rotação de chaves e monitoramento de acessos.",
        severity="CRITICAL",
    ),
    ThreatRisk(
        threat_type="Repudiation",
        threat_label="R - Repúdio",
        detail="Ações administrativas sem logging adequado.",
        mitigation="Habilitar CloudTrail em todas as regiões com log file validation.",
        severity="HIGH",
    ),
]

API_GATEWAY_THREATS = [
    ThreatRisk(
        threat_type="Spoofing",
        threat_label="S - Falsificação de Identidade",
        detail="APIs sem autenticação podem ser exploradas por atacantes.",
        mitigation="Implementar API keys, OAuth2/JWT e throttling.",
        severity="HIGH",
    ),
    ThreatRisk(
        threat_type="Denial of Service",
        threat_label="D - Negação de Serviço",
        detail="Requisições em massa podem sobrecarregar o backend.",
        mitigation="Configurar rate limiting, caching e request validation.",
        severity="MEDIUM",
    ),
    ThreatRisk(
        threat_type="Information Disclosure",
        threat_label="I - Vazamento de Informações",
        detail="Respostas de erro podem expor detalhes da infraestrutura.",
        mitigation="Customizar error responses e habilitar request/response logging.",
        severity="MEDIUM",
    ),
]

MESSAGING_THREATS = [
    ThreatRisk(
        threat_type="Tampering",
        threat_label="T - Adulteração",
        detail="Mensagens na fila podem ser modificadas em trânsito.",
        mitigation="Habilitar encryption in-transit e at-rest, usar VPC endpoints.",
        severity="HIGH",
    ),
    ThreatRisk(
        threat_type="Information Disclosure",
        threat_label="I - Vazamento de Informações",
        detail="Mensagens podem conter dados sensíveis em plaintext.",
        mitigation="Criptografar payloads sensíveis e usar client-side encryption.",
        severity="HIGH",
    ),
    ThreatRisk(
        threat_type="Denial of Service",
        threat_label="D - Negação de Serviço",
        detail="Message flooding pode saturar os consumidores.",
        mitigation="Configurar dead-letter queues e limites de concurrency.",
        severity="MEDIUM",
    ),
]

MONITORING_THREATS = [
    ThreatRisk(
        threat_type="Tampering",
        threat_label="T - Adulteração",
        detail="Logs podem ser modificados ou deletados para encobrir ataques.",
        mitigation="Enviar logs para conta separada, habilitar log file integrity validation.",
        severity="HIGH",
    ),
    ThreatRisk(
        threat_type="Information Disclosure",
        threat_label="I - Vazamento de Informações",
        detail="Logs podem conter dados sensíveis (tokens, PII, etc).",
        mitigation="Implementar log sanitization e acesso restrito a log groups.",
        severity="MEDIUM",
    ),
]

IDENTITY_THREATS = [
    ThreatRisk(
        threat_type="Spoofing",
        threat_label="S - Falsificação de Identidade",
        detail="Credenciais de usuários podem ser comprometidas via phishing.",
        mitigation="Habilitar MFA, password policies fortes e anomaly detection.",
        severity="CRITICAL",
    ),
    ThreatRisk(
        threat_type="Elevation of Privilege",
        threat_label="E - Elevação de Privilégio",
        detail="Usuários podem tentar escalar privilégios via federation flaws.",
        mitigation="Revisar trust policies, usar conditional access e RBAC.",
        severity="HIGH",
    ),
]

ML_AI_THREATS = [
    ThreatRisk(
        threat_type="Tampering",
        threat_label="T - Adulteração",
        detail="Dataset ou modelo pode ser envenenado (data/model poisoning).",
        mitigation="Validar integridade do dataset, usar model versioning e lineage tracking.",
        severity="HIGH",
    ),
    ThreatRisk(
        threat_type="Information Disclosure",
        threat_label="I - Vazamento de Informações",
        detail="Model inversion attacks podem extrair dados de treinamento.",
        mitigation="Aplicar differential privacy e limitar acesso aos endpoints de inferência.",
        severity="HIGH",
    ),
    ThreatRisk(
        threat_type="Denial of Service",
        threat_label="D - Negação de Serviço",
        detail="Inferências custosas podem esgotar recursos e gerar custos.",
        mitigation="Configurar auto-scaling limits, request throttling e budget alerts.",
        severity="MEDIUM",
    ),
]

SERVERLESS_THREATS = [
    ThreatRisk(
        threat_type="Elevation of Privilege",
        threat_label="E - Elevação de Privilégio",
        detail="Funções Lambda com IAM Role permissiva.",
        mitigation="Aplicar least privilege por função. Usar Resource-based policies.",
        severity="HIGH",
    ),
    ThreatRisk(
        threat_type="Denial of Service",
        threat_label="D - Negação de Serviço",
        detail="Execução recursiva ou loop infinito pode esgotar concurrency.",
        mitigation="Configurar reserved concurrency. Definir timeout adequado.",
        severity="MEDIUM",
    ),
    ThreatRisk(
        threat_type="Information Disclosure",
        threat_label="I - Vazamento de Informações",
        detail="Variáveis de ambiente podem expor secrets.",
        mitigation="Usar Secrets Manager ou Parameter Store para dados sensíveis.",
        severity="HIGH",
    ),
]

DEVOPS_THREATS = [
    ThreatRisk(
        threat_type="Elevation of Privilege",
        threat_label="E - Elevação de Privilégio",
        detail="Pipelines CI/CD geralmente têm permissões elevadas para deploy.",
        mitigation="Usar roles específicas por stage. Requerer aprovação para produção.",
        severity="CRITICAL",
    ),
    ThreatRisk(
        threat_type="Tampering",
        threat_label="T - Adulteração",
        detail="Código malicioso pode ser injetado no pipeline.",
        mitigation="Habilitar branch protection. Requerer code review. Assinar commits.",
        severity="HIGH",
    ),
    ThreatRisk(
        threat_type="Information Disclosure",
        threat_label="I - Vazamento de Informações",
        detail="Secrets podem ser expostos em logs de build.",
        mitigation="Usar Secrets Manager. Nunca hardcode secrets. Mascarar em logs.",
        severity="HIGH",
    ),
]

ANALYTICS_THREATS = [
    ThreatRisk(
        threat_type="Information Disclosure",
        threat_label="I - Vazamento de Informações",
        detail="Queries em data lakes podem expor dados sensíveis entre equipes.",
        mitigation="Implementar column-level security e row-level filtering.",
        severity="HIGH",
    ),
    ThreatRisk(
        threat_type="Tampering",
        threat_label="T - Adulteração",
        detail="Resultados de análises podem ser manipulados.",
        mitigation="Habilitar audit logging e versionamento de datasets.",
        severity="MEDIUM",
    ),
]

GROUPS_THREATS = [
    ThreatRisk(
        threat_type="Spoofing",
        threat_label="S - Falsificação de Identidade",
        detail="Agrupamentos de recursos podem mascarar acessos não autorizados.",
        mitigation="Definir boundaries claros com resource policies e tags obrigatórias.",
        severity="MEDIUM",
    ),
]

OTHER_THREATS = [
    ThreatRisk(
        threat_type="Spoofing",
        threat_label="S - Falsificação de Identidade",
        detail="Componente não categorizado requer revisão manual de segurança.",
        mitigation="Verificar autenticação e autorização manualmente.",
        severity="MEDIUM",
    ),
]
