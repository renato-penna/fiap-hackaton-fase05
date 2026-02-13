"""Motor de análise STRIDE para arquiteturas cloud."""

import logging
from typing import ClassVar

from src.stride.categories import CategoryClassifier, ComponentCategory
from src.stride.knowledge_base import (
    ANALYTICS_THREATS,
    API_GATEWAY_THREATS,
    COMPUTE_THREATS,
    DATABASE_THREATS,
    DEVOPS_THREATS,
    GROUPS_THREATS,
    IDENTITY_THREATS,
    MESSAGING_THREATS,
    ML_AI_THREATS,
    MONITORING_THREATS,
    NETWORK_THREATS,
    OTHER_THREATS,
    SECURITY_THREATS,
    SERVERLESS_THREATS,
    STORAGE_THREATS,
    ComponentAnalysis,
    ThreatRisk,
)

logger = logging.getLogger(__name__)


class StrideEngine:
    """Motor de análise de ameaças baseado na metodologia STRIDE.

    Classifica componentes cloud e gera relatórios de risco utilizando
    a base de conhecimento interna.
    """

    # Mapeia categoria → (element_type, stride_summary, description, threats)
    _CATEGORY_PROFILES: ClassVar[dict[ComponentCategory, tuple]] = {
        ComponentCategory.COMPUTE: (
            "Process",
            "S, T, E",
            "Recursos de computação (VMs, containers, instâncias)",
            COMPUTE_THREATS,
        ),
        ComponentCategory.DATABASE: (
            "Data Store",
            "T, I, D",
            "Bancos de dados relacionais e NoSQL",
            DATABASE_THREATS,
        ),
        ComponentCategory.STORAGE: (
            "Data Store",
            "I, T, R",
            "Armazenamento de objetos e arquivos",
            STORAGE_THREATS,
        ),
        ComponentCategory.NETWORK: (
            "Data Flow",
            "S, I, D",
            "Componentes de rede e conectividade",
            NETWORK_THREATS,
        ),
        ComponentCategory.SECURITY: (
            "Trust Boundary",
            "S, E, R",
            "Serviços de segurança e proteção",
            SECURITY_THREATS,
        ),
        ComponentCategory.API_GATEWAY: (
            "Process",
            "S, D, I",
            "API Gateways e serviços de integração",
            API_GATEWAY_THREATS,
        ),
        ComponentCategory.MESSAGING: (
            "Data Flow",
            "T, I, D",
            "Filas de mensagens e streaming de eventos",
            MESSAGING_THREATS,
        ),
        ComponentCategory.MONITORING: (
            "Data Store",
            "T, I",
            "Serviços de monitoramento e logging",
            MONITORING_THREATS,
        ),
        ComponentCategory.IDENTITY: (
            "External Entity",
            "S, E",
            "Provedores de identidade e autenticação",
            IDENTITY_THREATS,
        ),
        ComponentCategory.ML_AI: (
            "Process",
            "T, I, D",
            "Serviços de Machine Learning e IA",
            ML_AI_THREATS,
        ),
        ComponentCategory.SERVERLESS: (
            "Process",
            "I, D, E",
            "Funções e serviços serverless",
            SERVERLESS_THREATS,
        ),
        ComponentCategory.DEVOPS: (
            "Process",
            "T, I, E",
            "Ferramentas de CI/CD e automação",
            DEVOPS_THREATS,
        ),
        ComponentCategory.ANALYTICS: (
            "Data Store",
            "I, T",
            "Serviços de analytics e data lake",
            ANALYTICS_THREATS,
        ),
        ComponentCategory.GROUPS: (
            "Trust Boundary",
            "S",
            "Agrupamentos de recursos e boundaries",
            GROUPS_THREATS,
        ),
        ComponentCategory.OTHER: (
            "External Entity",
            "S",
            "Componente não categorizado",
            OTHER_THREATS,
        ),
    }

    def __init__(
        self,
        classifier: CategoryClassifier | None = None,
    ) -> None:
        """Inicializa o motor STRIDE.

        Args:
            classifier: Classificador de categorias. Se None, usa o padrão.
        """
        self._classifier = classifier or CategoryClassifier()
        logger.info(
            "StrideEngine inicializado com %d perfis de categoria",
            len(self._CATEGORY_PROFILES),
        )

    def analyze(self, component_name: str) -> ComponentAnalysis | None:
        """Analisa um componente individual usando STRIDE.

        Args:
            component_name: Nome do componente detectado pelo modelo.

        Returns:
            Resultado da análise ou None se componente inválido.
        """
        if not component_name or not component_name.strip():
            logger.warning("Nome de componente vazio recebido")
            return None

        category = self._classifier.classify(component_name)
        logger.debug(
            "Componente '%s' classificado como '%s'",
            component_name,
            category.value,
        )

        profile = self._CATEGORY_PROFILES.get(category)
        if profile is None:
            logger.warning("Sem perfil STRIDE para categoria '%s'", category.value)
            return self._build_generic_analysis(component_name, category)

        element_type, stride_summary, description, threats = profile
        return ComponentAnalysis(
            component=component_name,
            category=category.value,
            element_type=element_type,
            stride_summary=stride_summary,
            description=description,
            risks=list(threats),
        )

    def analyze_architecture(self, components: list[str]) -> dict:
        """Analisa uma lista de componentes e gera relatório consolidado.

        Args:
            components: Lista de nomes de componentes detectados.

        Returns:
            Dicionário com análise completa da arquitetura.
        """
        analyses: list[ComponentAnalysis] = []
        failed: list[str] = []

        for comp in components:
            result = self.analyze(comp)
            if result:
                analyses.append(result)
            else:
                failed.append(comp)

        risk_score = self._calculate_risk_score(analyses)

        return {
            "total_components": len(components),
            "analyzed": len(analyses),
            "failed": failed,
            "risk_score": risk_score,
            "risk_level": self._get_risk_level(risk_score),
            "components": [a.to_dict() for a in analyses],
        }

    @staticmethod
    def _calculate_risk_score(analyses: list[ComponentAnalysis]) -> float:
        """Calcula score de risco consolidado (0-100)."""
        if not analyses:
            return 0.0

        severity_weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
        total = sum(severity_weights.get(risk.severity, 0) for analysis in analyses for risk in analysis.risks)
        max_possible = len(analyses) * 3 * severity_weights["CRITICAL"]
        return min(round((total / max_possible) * 100, 1), 100.0) if max_possible else 0.0

    @staticmethod
    def _get_risk_level(score: float) -> str:
        """Converte score numérico em nível de risco textual."""
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _build_generic_analysis(component: str, category: ComponentCategory) -> ComponentAnalysis:
        """Cria análise genérica para componentes sem perfil específico."""
        return ComponentAnalysis(
            component=component,
            category=category.value,
            element_type="External Entity",
            stride_summary="S",
            description=f"Componente '{component}' sem análise específica",
            risks=[
                ThreatRisk(
                    threat_type="Spoofing",
                    threat_label="S - Falsificação de Identidade",
                    detail="Componente não categorizado requer revisão manual.",
                    mitigation="Verificar autenticação e autorização manualmente.",
                    severity="MEDIUM",
                )
            ],
        )
