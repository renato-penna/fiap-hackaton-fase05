"""Testes para o motor de análise STRIDE."""

import pytest

from src.stride.categories import CategoryClassifier, ComponentCategory
from src.stride.engine import StrideEngine


class TestCategoryClassifier:
    """Testes para classificação de componentes."""

    def test_exact_match(self, classifier: CategoryClassifier) -> None:
        assert classifier.classify("EC2") == ComponentCategory.COMPUTE

    def test_case_insensitive_partial(self, classifier: CategoryClassifier) -> None:
        assert classifier.classify("Amazon S3 Bucket") == ComponentCategory.STORAGE

    def test_unknown_component_returns_other(self, classifier: CategoryClassifier) -> None:
        assert classifier.classify("UnknownWidget123") == ComponentCategory.OTHER

    def test_empty_string(self, classifier: CategoryClassifier) -> None:
        assert classifier.classify("") == ComponentCategory.OTHER

    @pytest.mark.parametrize(
        "component,expected",
        [
            ("RDS", ComponentCategory.DATABASE),
            ("VPC", ComponentCategory.NETWORK),
            ("IAM", ComponentCategory.IDENTITY),
            ("SQS", ComponentCategory.MESSAGING),
            ("CloudWatch", ComponentCategory.MONITORING),
            ("CodePipeline", ComponentCategory.DEVOPS),
            ("Sagemaker", ComponentCategory.ML_AI),
            ("API Gateway", ComponentCategory.API_GATEWAY),
            ("Lambda", ComponentCategory.COMPUTE),
            ("S3", ComponentCategory.STORAGE),
            ("Amplify", ComponentCategory.SERVERLESS),
            ("Athena", ComponentCategory.ANALYTICS),
            ("groups", ComponentCategory.GROUPS),
            ("WAF", ComponentCategory.SECURITY),
        ],
    )
    def test_known_components(
        self,
        classifier: CategoryClassifier,
        component: str,
        expected: ComponentCategory,
    ) -> None:
        assert classifier.classify(component) == expected

    def test_custom_mappings(self) -> None:
        custom = {"MyService": "compute"}
        c = CategoryClassifier(custom_mappings=custom)
        assert c.classify("MyService") == ComponentCategory.COMPUTE

    def test_supported_components_not_empty(self, classifier: CategoryClassifier) -> None:
        assert len(classifier.supported_components) > 0


class TestStrideEngine:
    """Testes para o motor STRIDE."""

    def test_analyze_returns_result(self, stride_engine: StrideEngine) -> None:
        result = stride_engine.analyze("EC2")
        assert result is not None
        assert result.component == "EC2"
        assert result.category == "compute"

    def test_analyze_empty_string_returns_none(self, stride_engine: StrideEngine) -> None:
        assert stride_engine.analyze("") is None
        assert stride_engine.analyze("   ") is None

    def test_analyze_unknown_returns_other(self, stride_engine: StrideEngine) -> None:
        result = stride_engine.analyze("CompletelyUnknownThing")
        assert result is not None
        assert result.category == "other"

    def test_analyze_architecture(self, stride_engine: StrideEngine) -> None:
        components = ["EC2", "RDS", "S3", "IAM"]
        result = stride_engine.analyze_architecture(components)
        assert result["total_components"] == 4
        assert result["analyzed"] == 4
        assert "risk_score" in result
        assert "risk_level" in result
        assert len(result["components"]) == 4

    def test_analyze_architecture_empty_list(self, stride_engine: StrideEngine) -> None:
        result = stride_engine.analyze_architecture([])
        assert result["total_components"] == 0
        assert result["risk_score"] == 0.0
        assert result["risk_level"] == "LOW"

    def test_risk_level_mapping(self) -> None:
        assert StrideEngine._get_risk_level(80) == "CRITICAL"
        assert StrideEngine._get_risk_level(75) == "CRITICAL"
        assert StrideEngine._get_risk_level(50) == "HIGH"
        assert StrideEngine._get_risk_level(30) == "MEDIUM"
        assert StrideEngine._get_risk_level(25) == "MEDIUM"
        assert StrideEngine._get_risk_level(10) == "LOW"
        assert StrideEngine._get_risk_level(0) == "LOW"

    def test_calculate_risk_score_empty(self) -> None:
        assert StrideEngine._calculate_risk_score([]) == 0.0

    def test_component_analysis_to_dict(self, stride_engine: StrideEngine) -> None:
        result = stride_engine.analyze("S3")
        assert result is not None
        d = result.to_dict()
        assert "component" in d
        assert "category" in d
        assert "risks" in d
        assert isinstance(d["risks"], list)
        for risk in d["risks"]:
            assert "type" in risk
            assert "threat" in risk
            assert "detail" in risk
            assert "mitigation" in risk
            assert "severity" in risk

    def test_all_categories_have_profiles(self, stride_engine: StrideEngine) -> None:
        """Verifica que todas as categorias têm perfis no engine."""
        for category in ComponentCategory:
            assert category in stride_engine._CATEGORY_PROFILES, (
                f"Categoria {category.value} sem perfil no StrideEngine"
            )
