"""Interface Streamlit para análise de segurança de arquiteturas cloud."""

import json
import logging
import sys
from pathlib import Path

import streamlit as st
from PIL import Image

# Garante que o root do projeto está no path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from config.settings import get_config  # noqa: E402
from src.database import AnalysisRepository  # noqa: E402
from src.detection.detector import ArchitectureDetector, DetectionResult  # noqa: E402
from src.stride.engine import StrideEngine  # noqa: E402

# ─── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger(__name__)

# ─── Page Config ──────────────────────────────────────────────
st.set_page_config(
    page_title="Cloud Security Analyzer",
    page_icon="🛡️",
    layout="wide",
)

# ─── Constants ────────────────────────────────────────────────
SUPPORTED_FORMATS = ["png", "jpg", "jpeg", "webp"]

CATEGORY_EXAMPLES = {
    "Compute": "EC2, Lambda, EKS, Fargate, VM",
    "Database": "RDS, DynamoDB, Aurora, Redis, Cosmos DB",
    "Storage": "S3, EBS, EFS, Glacier, Blob Storage",
    "Network": "VPC, Load Balancer, CloudFront, Route 53",
    "Security": "IAM, WAF, KMS, Cognito, GuardDuty",
    "API Gateway": "API Gateway, AppSync, Apigee",
    "Messaging": "SQS, SNS, SES, EventBridge, Kinesis",
    "Monitoring": "CloudWatch, CloudTrail, X-Ray",
    "Identity": "User, Client, Active Directory",
    "ML/AI": "SageMaker, Rekognition, Vertex AI",
    "DevOps": "CodePipeline, ECR, CloudFormation",
    "Serverless": "Lambda, Step Functions, Cloud Functions",
    "Analytics": "Athena, Glue, BigQuery, Redshift",
    "Other": "Componentes não mapeados",
}


# ─── Resource Loading (cached) ───────────────────────────────
@st.cache_resource
def _load_resources():
    """Carrega detector e engine STRIDE com cache do Streamlit."""
    config = get_config()
    try:
        detector = ArchitectureDetector(
            model_path=config.model.path,
            confidence=config.model.confidence_threshold,
            iou_threshold=config.model.iou_threshold,
        )
        detector._ensure_model_loaded()
        engine = StrideEngine()
        return detector, engine, None
    except FileNotFoundError as exc:
        return None, None, str(exc)
    except Exception as exc:
        logger.exception("Falha ao carregar recursos")
        return None, None, f"Erro inesperado: {exc}"


def _render_sidebar() -> float:
    """Renderiza a barra lateral e retorna o threshold configurado."""
    with st.sidebar:
        st.title("🛡️ Cloud Security Analyzer")
        st.caption("Análise STRIDE automatizada para arquiteturas cloud")
        st.divider()

        threshold = st.slider(
            "Confiança mínima",
            min_value=0.1,
            max_value=0.9,
            value=0.25,
            step=0.05,
            help="Threshold de confiança para detecção de componentes.",
        )

        # Histórico
        st.divider()
        st.header("📜 Histórico")
        try:
            repo = AnalysisRepository()
            if repo.is_available():
                history = repo.get_history(limit=10)
                if history:
                    for record in history:
                        severity_icon = {
                            "CRITICAL": "🔴",
                            "HIGH": "🟠",
                            "MEDIUM": "🟡",
                            "LOW": "🟢",
                        }.get(record["risk_level"], "⚪")
                        col_info, col_del = st.columns([5, 1])
                        with col_info:
                            st.markdown(
                                f"{severity_icon} **{record['image_name']}** — "
                                f"Score: {record['risk_score']} ({record['risk_level']})"
                            )
                        with col_del:
                            if st.button(
                                "🗑️",
                                key=f"del_{record['id']}",
                                help="Remover do histórico",
                            ):
                                repo.delete_analysis(record["id"])
                                st.rerun()
                else:
                    st.caption("Nenhuma análise registrada.")
            else:
                st.caption("Banco de dados indisponível.")
        except Exception:
            st.caption("Banco de dados indisponível.")

        st.divider()
        st.header("ℹ\uFE0F Sobre")  # noqa: RUF001
        st.info(
            "**Modelo:** YOLO v8n (Fine-tuned)\n\n"
            "**Dataset:** AWS/Azure/GCP Diagrams\n\n"
            "**Metodologia:** STRIDE Threat Modeling"
        )

    return threshold


def _get_severity_icon(severity: str) -> str:
    """Retorna emoji correspondente ao nível de severidade."""
    return {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
    }.get(severity, "⚪")


def _render_results(detection: DetectionResult, analysis: dict) -> None:
    """Renderiza resultados da análise na interface."""
    # Métricas resumo
    col_a, col_b, col_c = st.columns(3)
    col_a.metric("Componentes", analysis["total_components"])
    col_b.metric("Score de Risco", f"{analysis['risk_score']:.1f}")
    col_c.metric(
        "Nível de Risco",
        f"{_get_severity_icon(analysis['risk_level'])} {analysis['risk_level']}",
    )

    st.divider()

    # Detalhes por componente
    st.subheader("🔍 Análise STRIDE por Componente")
    for comp in analysis["components"]:
        max_sev = _get_max_severity_badge(comp["risks"])
        with st.expander(f"{max_sev} **{comp['component']}** — {comp['category']} | STRIDE: {comp['stride_summary']}"):
            st.markdown(f"**Tipo de Elemento:** {comp['element_type']}")
            st.markdown(f"**Descrição:** {comp['description']}")
            st.divider()

            for risk in comp["risks"]:
                icon = _get_severity_icon(risk["severity"])
                st.markdown(
                    f"#### {icon} {risk['threat']} ({risk['severity']})\n\n"
                    f"**Detalhe:** {risk['detail']}\n\n"
                    f"**Mitigação:** {risk['mitigation']}\n\n"
                    f"---"
                )

    # Componentes não analisados
    if analysis.get("failed"):
        st.warning(f"⚠️ {len(analysis['failed'])} componente(s) não analisados: {', '.join(analysis['failed'])}")


def _get_max_severity_badge(risks: list) -> str:
    """Retorna o badge do maior severity entre os riscos."""
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    if not risks:
        return "⚪"
    max_risk = max(risks, key=lambda r: severity_order.get(r.get("severity", "LOW"), 0))
    return _get_severity_icon(max_risk.get("severity", "LOW"))


def _render_detection_details(detection: DetectionResult) -> None:
    """Renderiza detalhes das detecções em uma tabela."""
    if detection.count == 0:
        return

    st.subheader("📊 Detecções do Modelo")
    data = []
    for det in sorted(detection.detections, key=lambda d: d.confidence, reverse=True):
        data.append(
            {
                "Componente": det.class_name,
                "Confiança": f"{det.confidence:.1%}",
                "BBox": f"({int(det.bbox[0])}, {int(det.bbox[1])}) → ({int(det.bbox[2])}, {int(det.bbox[3])})",
            }
        )
    st.table(data)


def _render_tips() -> None:
    """Renderiza dicas de uso quando não há upload."""
    st.info("👆 Faça upload de um diagrama de arquitetura cloud para iniciar a análise.")

    with st.expander("💡 Dicas de Uso", expanded=True):
        st.markdown(
            "### Como obter melhores resultados\n\n"
            "1. Use diagramas com **ícones oficiais** AWS/Azure/GCP\n"
            "2. Resolução mínima recomendada: **800x600** pixels\n"
            "3. Evite diagramas muito complexos (>30 componentes)\n"
            "4. Ajuste o **threshold** na barra lateral se componentes não forem detectados\n"
            "5. Formatos suportados: **PNG, JPG, JPEG, WebP**\n\n"
            "### Categorias detectadas"
        )
        table_md = "| Categoria | Exemplos |\n|-----------|----------|\n"
        for cat, examples in CATEGORY_EXAMPLES.items():
            table_md += f"| {cat} | {examples} |\n"
        st.markdown(table_md)


def _save_to_database(uploaded_file_name: str, analysis: dict) -> None:
    """Tenta salvar a análise no banco de dados."""
    try:
        repo = AnalysisRepository()
        if repo.is_available():
            repo.save_analysis(
                image_name=uploaded_file_name,
                total_components=analysis["total_components"],
                risk_score=analysis["risk_score"],
                risk_level=analysis["risk_level"],
                components_json=json.dumps(analysis["components"], ensure_ascii=False),
            )
            st.toast("✅ Análise salva no histórico")
        else:
            logger.debug("Banco indisponível — análise não persistida")
    except Exception:
        logger.debug("Falha ao salvar no banco — continuando sem persistência")


# ─── Main ────────────────────────────────────────────────────
def main() -> None:
    """Entry-point da aplicação Streamlit."""
    threshold = _render_sidebar()

    detector, engine, load_error = _load_resources()

    if load_error:
        st.error(f"⚠️ Erro ao carregar modelo: {load_error}")
        st.warning(
            "Verifique se:\n"
            "1. O arquivo `best.pt` existe em `models/`\n"
            "2. O modelo foi treinado corretamente\n"
            "3. O pacote `ultralytics` está instalado"
        )
        st.stop()

    st.header("📤 Upload do Diagrama de Arquitetura")
    uploaded_file = st.file_uploader(
        "Arraste seu diagrama de arquitetura aqui",
        type=SUPPORTED_FORMATS,
        help="Suporta imagens PNG, JPG e WebP de diagramas AWS, Azure e GCP",
    )

    if uploaded_file is None:
        _render_tips()
        return

    image = Image.open(uploaded_file)
    col_left, col_right = st.columns([1, 1])

    with col_left:
        st.subheader("📋 Diagrama Original")
        st.image(image, use_container_width=True)

    if st.button("🔍 Analisar Arquitetura", type="primary", use_container_width=True):
        with st.spinner("🔄 Analisando diagrama... Isso pode levar alguns segundos."):
            detector._confidence = threshold
            detection = detector.detect(image)

            if detection.count == 0:
                st.warning(
                    "❌ Nenhum componente detectado. Tente:\n"
                    "- Reduzir o threshold de confiança\n"
                    "- Usar um diagrama com ícones mais claros\n"
                    "- Verificar a resolução da imagem"
                )
                return

            analysis = engine.analyze_architecture(detection.component_names)

        # Substitui imagem original pela anotada com bounding boxes
        with col_left:
            st.subheader("🔎 Componentes Detectados")
            if detection.annotated_image is not None:
                st.image(detection.annotated_image, use_container_width=True)
            else:
                st.image(image, use_container_width=True)

        with col_right:
            st.subheader("📊 Resultado da Análise")
            _render_results(detection, analysis)

        st.divider()
        _render_detection_details(detection)

        # JSON exportável
        with st.expander("📥 Exportar JSON"):
            st.json(analysis)

        # Salvar no banco
        _save_to_database(uploaded_file.name, analysis)


if __name__ == "__main__":
    main()
