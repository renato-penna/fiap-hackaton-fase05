"""Testes para a base de conhecimento STRIDE."""

import pytest

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


class TestThreatRisk:
    """Testes para ThreatRisk."""

    def test_creation(self) -> None:
        risk = ThreatRisk(
            threat_type="Spoofing",
            threat_label="S - Falsificação",
            detail="Detalhe",
            mitigation="Mitigação",
            severity="HIGH",
        )
        assert risk.threat_type == "Spoofing"
        assert risk.severity == "HIGH"

    def test_is_frozen(self) -> None:
        risk = ThreatRisk("Spoofing", "S", "d", "m", "HIGH")
        with pytest.raises(AttributeError):
            risk.severity = "LOW"


class TestComponentAnalysis:
    """Testes para ComponentAnalysis."""

    def test_risk_count(self) -> None:
        analysis = ComponentAnalysis(
            component="EC2",
            category="compute",
            element_type="Process",
            stride_summary="S, T, E",
            description="desc",
            risks=COMPUTE_THREATS,
        )
        assert analysis.risk_count == len(COMPUTE_THREATS)

    def test_max_severity(self) -> None:
        analysis = ComponentAnalysis(
            component="EC2",
            category="compute",
            element_type="Process",
            stride_summary="S, T, E",
            description="desc",
            risks=COMPUTE_THREATS,
        )
        assert analysis.max_severity == "CRITICAL"

    def test_max_severity_empty(self) -> None:
        analysis = ComponentAnalysis(
            component="X",
            category="x",
            element_type="x",
            stride_summary="",
            description="",
            risks=[],
        )
        assert analysis.max_severity == "LOW"

    def test_to_dict_structure(self) -> None:
        analysis = ComponentAnalysis(
            component="S3",
            category="storage",
            element_type="Data Store",
            stride_summary="I, T, R",
            description="Storage",
            risks=STORAGE_THREATS,
        )
        d = analysis.to_dict()
        assert d["component"] == "S3"
        assert len(d["risks"]) == len(STORAGE_THREATS)


class TestThreatDataIntegrity:
    """Verifica integridade de todos os conjuntos de threats."""

    @pytest.mark.parametrize(
        "threats,name",
        [
            (COMPUTE_THREATS, "COMPUTE"),
            (DATABASE_THREATS, "DATABASE"),
            (STORAGE_THREATS, "STORAGE"),
            (NETWORK_THREATS, "NETWORK"),
            (SECURITY_THREATS, "SECURITY"),
            (API_GATEWAY_THREATS, "API_GATEWAY"),
            (MESSAGING_THREATS, "MESSAGING"),
            (MONITORING_THREATS, "MONITORING"),
            (IDENTITY_THREATS, "IDENTITY"),
            (ML_AI_THREATS, "ML_AI"),
            (SERVERLESS_THREATS, "SERVERLESS"),
            (DEVOPS_THREATS, "DEVOPS"),
            (ANALYTICS_THREATS, "ANALYTICS"),
            (GROUPS_THREATS, "GROUPS"),
            (OTHER_THREATS, "OTHER"),
        ],
    )
    def test_threats_not_empty(self, threats, name) -> None:
        assert len(threats) > 0, f"{name}_THREATS está vazio"

    @pytest.mark.parametrize(
        "threats,name",
        [
            (COMPUTE_THREATS, "COMPUTE"),
            (DATABASE_THREATS, "DATABASE"),
            (STORAGE_THREATS, "STORAGE"),
            (NETWORK_THREATS, "NETWORK"),
            (SECURITY_THREATS, "SECURITY"),
            (API_GATEWAY_THREATS, "API_GATEWAY"),
            (MESSAGING_THREATS, "MESSAGING"),
            (MONITORING_THREATS, "MONITORING"),
            (IDENTITY_THREATS, "IDENTITY"),
            (ML_AI_THREATS, "ML_AI"),
            (SERVERLESS_THREATS, "SERVERLESS"),
            (DEVOPS_THREATS, "DEVOPS"),
            (ANALYTICS_THREATS, "ANALYTICS"),
            (GROUPS_THREATS, "GROUPS"),
            (OTHER_THREATS, "OTHER"),
        ],
    )
    def test_threats_have_valid_severity(self, threats, name) -> None:
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for risk in threats:
            assert risk.severity in valid, f"{name}: severity '{risk.severity}' inválida em {risk.threat_type}"
