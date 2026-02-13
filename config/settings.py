"""Configurações centralizadas do projeto."""

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class ModelConfig:
    """Configurações do modelo YOLO."""

    path: Path = BASE_DIR / "models" / "best.pt"
    confidence_threshold: float = 0.25
    iou_threshold: float = 0.45
    image_size: int = 416
    device: str = "auto"


@dataclass(frozen=True)
class TrainingConfig:
    """Configurações de treinamento."""

    epochs: int = 30
    batch_size: int = 16
    image_size: int = 416
    learning_rate: float = 4.8e-5
    optimizer: str = "AdamW"
    workers: int = 8
    base_model: str = "yolo11n.pt"
    project_name: str = "mvp_security"


@dataclass(frozen=True)
class DatabaseConfig:
    """Configurações do banco de dados."""

    host: str = field(default_factory=lambda: os.getenv("DB_HOST", "localhost"))
    port: int = field(default_factory=lambda: int(os.getenv("DB_PORT", "5432")))
    name: str = field(default_factory=lambda: os.getenv("DB_NAME", "security_analyzer"))
    user: str = field(default_factory=lambda: os.getenv("DB_USER", "postgres"))
    password: str = field(default_factory=lambda: os.getenv("DB_PASSWORD", "postgres"))

    @property
    def url(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"


@dataclass(frozen=True)
class AppConfig:
    """Configuração principal da aplicação."""

    model: ModelConfig = field(default_factory=ModelConfig)
    training: TrainingConfig = field(default_factory=TrainingConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    data_dir: Path = BASE_DIR / "data"
    diagrams_dir: Path = BASE_DIR / "data" / "diagrams"
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))


def get_config() -> AppConfig:
    """Factory para obter configuração da aplicação."""
    return AppConfig()
