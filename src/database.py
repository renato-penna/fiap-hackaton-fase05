"""
Database Layer - Persistência de Relatórios STRIDE
===================================================

Módulo responsável pela conexão com PostgreSQL e operações CRUD
para relatórios de análise de segurança.

Autor: MVP Pós-Graduação FIAP
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any

import psycopg2
from psycopg2.extras import RealDictCursor, Json


# Configuração via variáveis de ambiente (com defaults para dev local)
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "dbname": os.getenv("DB_NAME", "stride_reports"),
    "user": os.getenv("DB_USER", "stride"),
    "password": os.getenv("DB_PASSWORD", "stride_mvp_2026"),
}


def get_connection():
    """Cria e retorna uma conexão com o PostgreSQL."""
    return psycopg2.connect(**DB_CONFIG)


def is_db_available() -> bool:
    """Verifica se o banco de dados está acessível."""
    try:
        conn = get_connection()
        conn.close()
        return True
    except Exception:
        return False


def save_report(
    filename: str,
    risk_level: str,
    risk_score: float,
    total_components: int,
    total_risks: int,
    security_controls: List[str],
    detections: List[Dict],
    stride_analyses: List[Dict],
) -> Optional[int]:
    """
    Persiste um relatório STRIDE no banco de dados.

    Returns:
        ID do relatório inserido ou None em caso de erro.
    """
    sql = """
        INSERT INTO reports (
            filename, risk_level, risk_score,
            total_components, total_risks, security_controls,
            detections, stride_analyses
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s
        )
        RETURNING id;
    """
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute(sql, (
                    filename,
                    risk_level,
                    risk_score,
                    total_components,
                    total_risks,
                    Json(security_controls),
                    Json(detections),
                    Json(stride_analyses),
                ))
                report_id = cur.fetchone()[0]
        conn.close()
        return report_id
    except Exception as e:
        print(f"[DB] Erro ao salvar relatório: {e}")
        return None


def list_reports(limit: int = 50) -> List[Dict[str, Any]]:
    """Retorna os relatórios mais recentes."""
    sql = """
        SELECT id, created_at, filename, risk_level, risk_score,
               total_components, total_risks, security_controls
        FROM reports
        ORDER BY created_at DESC
        LIMIT %s;
    """
    try:
        conn = get_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, (limit,))
            rows = cur.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[DB] Erro ao listar relatórios: {e}")
        return []


def get_report(report_id: int) -> Optional[Dict[str, Any]]:
    """Retorna um relatório completo pelo ID."""
    sql = """
        SELECT id, created_at, filename, risk_level, risk_score,
               total_components, total_risks, security_controls,
               detections, stride_analyses
        FROM reports
        WHERE id = %s;
    """
    try:
        conn = get_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, (report_id,))
            row = cur.fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception as e:
        print(f"[DB] Erro ao buscar relatório: {e}")
        return None


def delete_report(report_id: int) -> bool:
    """Remove um relatório pelo ID."""
    sql = "DELETE FROM reports WHERE id = %s;"
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute(sql, (report_id,))
                deleted = cur.rowcount > 0
        conn.close()
        return deleted
    except Exception as e:
        print(f"[DB] Erro ao deletar relatório: {e}")
        return False


def get_stats() -> Dict[str, Any]:
    """Retorna estatísticas agregadas dos relatórios."""
    sql = """
        SELECT
            COUNT(*)                          AS total_reports,
            ROUND(AVG(risk_score)::numeric, 2) AS avg_risk_score,
            MAX(risk_score)                    AS max_risk_score,
            SUM(total_components)              AS total_components_analyzed,
            SUM(total_risks)                   AS total_risks_found,
            COUNT(CASE WHEN risk_level = 'CRITICAL' THEN 1 END) AS critical_count,
            COUNT(CASE WHEN risk_level = 'HIGH'     THEN 1 END) AS high_count,
            COUNT(CASE WHEN risk_level = 'MEDIUM'   THEN 1 END) AS medium_count,
            COUNT(CASE WHEN risk_level = 'LOW'      THEN 1 END) AS low_count
        FROM reports;
    """
    try:
        conn = get_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql)
            row = cur.fetchone()
        conn.close()
        return dict(row) if row else {}
    except Exception as e:
        print(f"[DB] Erro ao buscar estatísticas: {e}")
        return {}
