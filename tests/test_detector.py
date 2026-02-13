"""Testes para o detector de componentes."""


import pytest

from src.detection.detector import ArchitectureDetector, Detection, DetectionResult


class TestDetection:
    """Testes para o dataclass Detection."""

    def test_detection_creation(self) -> None:
        det = Detection(class_name="EC2", confidence=0.95, bbox=(10, 20, 100, 200))
        assert det.class_name == "EC2"
        assert det.confidence == 0.95

    def test_detection_is_frozen(self) -> None:
        det = Detection(class_name="EC2", confidence=0.95, bbox=(10, 20, 100, 200))
        with pytest.raises(AttributeError):
            det.class_name = "RDS"  # type: ignore[misc]


class TestDetectionResult:
    """Testes para DetectionResult."""

    def test_component_names_unique(self) -> None:
        result = DetectionResult(
            detections=[
                Detection("EC2", 0.9, (0, 0, 1, 1)),
                Detection("EC2", 0.8, (2, 2, 3, 3)),
                Detection("RDS", 0.7, (4, 4, 5, 5)),
            ]
        )
        assert sorted(result.component_names) == ["EC2", "RDS"]

    def test_count(self) -> None:
        result = DetectionResult(
            detections=[
                Detection("EC2", 0.9, (0, 0, 1, 1)),
                Detection("RDS", 0.7, (4, 4, 5, 5)),
            ]
        )
        assert result.count == 2

    def test_empty_result(self) -> None:
        result = DetectionResult()
        assert result.count == 0
        assert result.component_names == []


class TestArchitectureDetector:
    """Testes para o detector (sem modelo real)."""

    def test_missing_model_raises(self) -> None:
        detector = ArchitectureDetector(model_path="/nonexistent/model.pt")
        with pytest.raises(FileNotFoundError, match="Modelo não encontrado"):
            detector._ensure_model_loaded()
