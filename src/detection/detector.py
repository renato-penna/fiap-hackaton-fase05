"""Detector de componentes em diagramas de arquitetura cloud."""

import logging
from dataclasses import dataclass, field
from pathlib import Path

from PIL import Image

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Detection:
    """Resultado individual de detecção."""

    class_name: str
    confidence: float
    bbox: tuple  # (x1, y1, x2, y2)


@dataclass
class DetectionResult:
    """Resultado consolidado da detecção em uma imagem."""

    detections: list[Detection] = field(default_factory=list)
    image_path: str | None = None
    annotated_image: Image.Image | None = None

    @property
    def component_names(self) -> list[str]:
        """Nomes únicos dos componentes detectados."""
        return list({d.class_name for d in self.detections})

    @property
    def count(self) -> int:
        return len(self.detections)


class ArchitectureDetector:
    """Detecta componentes cloud em diagramas de arquitetura usando YOLO.

    Args:
        model_path: Caminho para o arquivo de pesos do modelo (.pt).
        confidence: Threshold mínimo de confiança para detecções.
        iou_threshold: Threshold de IoU para NMS.
    """

    def __init__(
        self,
        model_path: str | Path,
        confidence: float = 0.25,
        iou_threshold: float = 0.45,
    ) -> None:
        self._model_path = Path(model_path)
        self._confidence = confidence
        self._iou_threshold = iou_threshold
        self._model = None

    def _ensure_model_loaded(self) -> None:
        """Carrega o modelo YOLO sob demanda (lazy loading)."""
        if self._model is not None:
            return

        if not self._model_path.exists():
            raise FileNotFoundError(
                f"Modelo não encontrado: {self._model_path}. Verifique se o arquivo best.pt está na pasta models/."
            )

        try:
            from ultralytics import YOLO

            self._model = YOLO(str(self._model_path))
            logger.info(
                "Modelo carregado: %s (%d classes)",
                self._model_path.name,
                len(self._model.names),
            )
        except Exception as exc:
            logger.error("Falha ao carregar modelo: %s", exc)
            raise

    def detect(self, image: Image.Image) -> DetectionResult:
        """Executa detecção em uma imagem PIL.

        Args:
            image: Imagem PIL do diagrama.

        Returns:
            DetectionResult com todas as detecções.
        """
        self._ensure_model_loaded()

        results = self._model(
            image,
            conf=self._confidence,
            iou=self._iou_threshold,
            verbose=False,
        )

        detections: list[Detection] = []
        annotated: Image.Image | None = None
        for result in results:
            for box in result.boxes:
                class_id = int(box.cls[0])
                detections.append(
                    Detection(
                        class_name=self._model.names[class_id],
                        confidence=float(box.conf[0]),
                        bbox=tuple(box.xyxy[0].tolist()),
                    )
                )
            # Gera imagem anotada com bounding boxes via YOLO
            if annotated is None:
                annotated = Image.fromarray(result.plot()[:, :, ::-1])  # BGR → RGB

        logger.info("Detectados %d componentes", len(detections))
        return DetectionResult(detections=detections, annotated_image=annotated)

    @property
    def class_names(self) -> dict:
        """Retorna mapeamento de IDs para nomes de classes."""
        self._ensure_model_loaded()
        return dict(self._model.names)
