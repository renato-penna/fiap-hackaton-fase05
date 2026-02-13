"""Módulo de treinamento do modelo YOLO para detecção de componentes cloud."""

import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import get_config  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger(__name__)


def train_model(
    data_yaml: str,
    epochs: int | None = None,
    batch_size: int | None = None,
    image_size: int | None = None,
) -> None:
    """Executa treinamento do modelo YOLO.

    Args:
        data_yaml: Caminho para o arquivo data.yaml do dataset.
        epochs: Número de épocas (override do config).
        batch_size: Tamanho do batch (override do config).
        image_size: Tamanho da imagem (override do config).
    """
    from ultralytics import YOLO

    config = get_config()
    training = config.training

    _epochs = epochs or training.epochs
    _batch = batch_size or training.batch_size
    _imgsz = image_size or training.image_size

    logger.info("Iniciando treinamento:")
    logger.info("  Base model: %s", training.base_model)
    logger.info("  Epochs: %d", _epochs)
    logger.info("  Batch size: %d", _batch)
    logger.info("  Image size: %d", _imgsz)
    logger.info("  Optimizer: %s", training.optimizer)
    logger.info("  Learning rate: %s", training.learning_rate)

    # Detecta GPU
    try:
        import torch

        device = "0" if torch.cuda.is_available() else "cpu"
        logger.info("Dispositivo: %s", "GPU" if device == "0" else "CPU")
    except ImportError:
        device = "cpu"
        logger.info("PyTorch não encontrado, usando CPU")

    base_model_path = PROJECT_ROOT / "models" / training.base_model
    if not base_model_path.exists():
        logger.warning(
            "Base model '%s' não encontrado localmente, tentando download...",
            training.base_model,
        )
        model = YOLO(training.base_model)
    else:
        model = YOLO(str(base_model_path))

    results = model.train(
        data=data_yaml,
        epochs=_epochs,
        batch=_batch,
        imgsz=_imgsz,
        optimizer=training.optimizer,
        lr0=training.learning_rate,
        workers=training.workers,
        project=str(PROJECT_ROOT / "runs"),
        name=training.project_name,
        exist_ok=True,
        device=device,
        verbose=True,
    )

    logger.info("Treinamento concluído!")
    logger.info("Resultados salvos em: runs/%s", training.project_name)

    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Treinar modelo YOLO")
    parser.add_argument(
        "--data",
        type=str,
        required=True,
        help="Caminho para o data.yaml",
    )
    parser.add_argument("--epochs", type=int, default=None)
    parser.add_argument("--batch", type=int, default=None)
    parser.add_argument("--imgsz", type=int, default=None)

    args = parser.parse_args()
    train_model(
        data_yaml=args.data,
        epochs=args.epochs,
        batch_size=args.batch,
        image_size=args.imgsz,
    )
