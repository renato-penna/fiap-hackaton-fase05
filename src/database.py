"""Camada de persistência para histórico de análises."""

import logging
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime

import psycopg2
from psycopg2.extras import RealDictCursor, RealDictRow

from config.settings import DatabaseConfig

logger = logging.getLogger(__name__)


class AnalysisRepository:
    """Repositório para operações de banco de dados de análises.

    Usa context manager para gerenciamento seguro de conexão.
    """

    def __init__(self, config: DatabaseConfig | None = None) -> None:
        self._config = config or DatabaseConfig()

    @contextmanager
    def _get_cursor(self) -> Generator:
        """Context manager para cursor do banco de dados."""
        conn = None
        try:
            conn = psycopg2.connect(self._config.url)
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            yield cursor
            conn.commit()
        except psycopg2.Error as exc:
            if conn:
                conn.rollback()
            logger.error("Erro no banco de dados: %s", exc)
            raise
        finally:
            if conn:
                conn.close()

    def save_analysis(
        self,
        image_name: str,
        total_components: int,
        risk_score: float,
        risk_level: str,
        components_json: str,
    ) -> int | None:
        """Salva resultado de análise no banco.

        Returns:
            ID do registro inserido ou None em caso de falha.
        """
        query = """
            INSERT INTO analysis_history
                (image_name, total_components, risk_score, risk_level, components, created_at)
            VALUES
                (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """
        try:
            with self._get_cursor() as cursor:
                cursor.execute(
                    query,
                    (image_name, total_components, risk_score, risk_level, components_json, datetime.utcnow()),
                )
                row = cursor.fetchone()
                record_id = row["id"] if row else None
                logger.info("Análise salva com ID=%s", record_id)
                return record_id
        except Exception:
            logger.exception("Falha ao salvar análise")
            return None

    def get_history(self, limit: int = 20) -> list[RealDictRow]:
        """Recupera histórico de análises recentes."""
        query = """
            SELECT id, image_name, total_components, risk_score, risk_level, created_at
            FROM analysis_history
            ORDER BY created_at DESC
            LIMIT %s
        """
        try:
            with self._get_cursor() as cursor:
                cursor.execute(query, (limit,))
                return cursor.fetchall()
        except Exception:
            logger.exception("Falha ao buscar histórico")
            return []

    def delete_analysis(self, record_id: int) -> bool:
        """Remove um registro de análise pelo ID.

        Returns:
            True se o registro foi removido, False caso contrário.
        """
        query = "DELETE FROM analysis_history WHERE id = %s"
        try:
            with self._get_cursor() as cursor:
                cursor.execute(query, (record_id,))
                deleted = cursor.rowcount > 0
                if deleted:
                    logger.info("Análise ID=%s removida", record_id)
                return deleted
        except Exception:
            logger.exception("Falha ao remover análise ID=%s", record_id)
            return False

    def is_available(self) -> bool:
        """Verifica se o banco está acessível."""
        try:
            with self._get_cursor() as cursor:
                cursor.execute("SELECT 1")
                return True
        except Exception:
            return False
