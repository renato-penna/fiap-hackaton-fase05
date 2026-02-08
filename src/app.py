"""
Cloud Architecture Security Analyzer - MVP
===========================================

Aplicação Streamlit para análise visual de diagramas de arquitetura cloud
usando detecção de objetos (YOLO) e análise STRIDE para vulnerabilidades.

Autor: MVP Pós-Graduação FIAP
"""

import streamlit as st
from ultralytics import YOLO
from stride_engine import StrideEngine
from PIL import Image
import os
import json

# --- 1. CONFIGURAÇÃO DA PÁGINA ---
st.set_page_config(
    page_title="MVP Security Audit",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS customizado para melhor visualização
st.markdown("""
<style>
    .risk-critical { background-color: #ff4444; color: white; padding: 3px 8px; border-radius: 4px; }
    .risk-high { background-color: #ff8800; color: white; padding: 3px 8px; border-radius: 4px; }
    .risk-medium { background-color: #ffcc00; color: black; padding: 3px 8px; border-radius: 4px; }
    .risk-low { background-color: #44aa44; color: white; padding: 3px 8px; border-radius: 4px; }
    .component-tag { background-color: #0066cc; color: white; padding: 2px 6px; border-radius: 3px; margin: 2px; display: inline-block; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Cloud Architecture Security Analyzer")
st.markdown("""
**MVP de Pós-Graduação FIAP** | Detecção Visual + Análise STRIDE  
Faça upload de um diagrama de arquitetura AWS/Azure para identificar componentes e vulnerabilidades automaticamente.
""")

# --- 2. SIDEBAR COM CONFIGURAÇÕES ---
with st.sidebar:
    st.header("⚙️ Configurações")
    
    # Configurações do modelo
    confidence_threshold = st.slider(
        "Threshold de Confiança", 
        min_value=0.1, 
        max_value=0.9, 
        value=0.35,  # Valor mais baixo para não perder detecções
        step=0.05,
        help="Componentes com confiança abaixo deste valor serão ignorados"
    )
    
    iou_threshold = st.slider(
        "Threshold IoU (NMS)", 
        min_value=0.1, 
        max_value=0.9, 
        value=0.45,
        step=0.05,
        help="Controla a supressão de detecções duplicadas"
    )
    
    st.divider()
    
    # Informações do modelo
    st.header("ℹ️ Sobre o Modelo")
    st.info("""
    **Modelo:** YOLOv8n (Fine-tuned)  
    **Dataset:** AWS/Azure System Diagrams  
    **Classes:** Categorias de componentes cloud  
    **Metodologia:** STRIDE Threat Modeling
    """)

# --- 3. CARREGAMENTO DO MODELO ---
pasta_atual = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(pasta_atual, "..", "models", "best.pt")

@st.cache_resource
def load_resources():
    """Carrega modelo YOLO e motor STRIDE com cache."""
    caminho_final = os.path.normpath(MODEL_PATH)
    
    if not os.path.exists(caminho_final):
        return None, None, f"Modelo não encontrado em: {caminho_final}"
    
    try:
        model_loaded = YOLO(caminho_final)
        engine_loaded = StrideEngine()
        return model_loaded, engine_loaded, None
    except Exception as e:
        return None, None, str(e)

model, engine, load_error = load_resources()

if load_error:
    st.error(f"⚠️ ERRO ao carregar recursos: {load_error}")
    st.warning("""
    **Verifique se:**
    1. O arquivo `best.pt` existe na pasta `models/`
    2. O modelo foi treinado corretamente no Colab
    3. O arquivo foi copiado do Google Drive para o projeto local
    """)
    st.stop()

# --- 4. INTERFACE DE UPLOAD ---
st.header("📤 Upload do Diagrama")

uploaded_file = st.file_uploader(
    "Arraste seu diagrama de arquitetura aqui",
    type=['png', 'jpg', 'jpeg', 'webp'],
    help="Suporta imagens PNG, JPG e WebP"
)

# --- 5. PROCESSAMENTO E ANÁLISE ---
if uploaded_file is not None and model is not None:
    image = Image.open(uploaded_file)
    
    # Layout em duas colunas
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("📋 1. Diagrama Original")
        st.image(image, use_container_width=True)

    # Botão de análise
    if st.button("🔍 Analisar Arquitetura", type="primary", use_container_width=True):
        
        with st.spinner('🤖 Detectando componentes com IA...'):
            # Executa inferência com configurações do sidebar
            results = model(
                image, 
                conf=confidence_threshold, 
                iou=iou_threshold,
                verbose=False
            )
            
            # Imagem com bounding boxes
            res_plotted = results[0].plot()
            
            # Extrai componentes detectados com confiança
            detections = []
            componentes_unicos = set()
            
            for r in results:
                for box in r.boxes:
                    cls_id = int(box.cls[0])
                    conf = float(box.conf[0])
                    nome_classe = model.names[cls_id]
                    componentes_unicos.add(nome_classe)
                    detections.append({
                        "class": nome_classe,
                        "confidence": conf,
                        "box": box.xyxy[0].tolist()
                    })
        
        # Mostra resultados visuais
        with col1:
            st.subheader("🔎 2. Detecção Visual")
            st.image(res_plotted, caption="Componentes Identificados", use_container_width=True)
            
            # Estatísticas da detecção
            st.metric("Total de Detecções", len(detections))
            st.metric("Componentes Únicos", len(componentes_unicos))
        
        # Análise STRIDE
        with col2:
            st.subheader("📊 3. Relatório de Segurança STRIDE")
            
            if not componentes_unicos:
                st.warning("⚠️ Nenhum componente foi detectado. Tente:")
                st.markdown("""
                - Usar uma imagem de maior resolução
                - Verificar se o diagrama contém ícones AWS/Azure padrão
                - Reduzir o threshold de confiança no sidebar
                """)
            else:
                # Resumo dos componentes
                st.success(f"✅ **{len(componentes_unicos)} componentes** identificados")
                
                # Tags visuais dos componentes
                tags_html = " ".join([
                    f'<span class="component-tag">{c}</span>' 
                    for c in sorted(componentes_unicos)
                ])
                st.markdown(tags_html, unsafe_allow_html=True)
                st.divider()
                
                # Análise completa da arquitetura
                arch_analysis = engine.analyze_architecture(list(componentes_unicos))
                
                # Score de risco visual
                risk_color_map = {
                    'LOW': 'risk-low',
                    'MEDIUM': 'risk-medium', 
                    'HIGH': 'risk-high',
                    'CRITICAL': 'risk-critical'
                }
                risk_class = risk_color_map.get(arch_analysis['risk_level'], 'risk-medium')
                
                col_score1, col_score2 = st.columns(2)
                with col_score1:
                    st.markdown(f"""
                    <h3>Nível de Risco: <span class="{risk_class}">{arch_analysis['risk_level']}</span></h3>
                    """, unsafe_allow_html=True)
                with col_score2:
                    st.metric("Score de Risco", f"{arch_analysis['risk_score']:.0%}")
                
                # Controles de segurança detectados
                if arch_analysis['security_controls']:
                    st.success(f"🛡️ **Controles de segurança detectados:** {', '.join(arch_analysis['security_controls'])}")
                else:
                    st.warning("⚠️ Nenhum controle de segurança (WAF, Firewall, etc.) foi detectado!")
                
                st.divider()
                
                # Análises detalhadas por componente
                for analise in arch_analysis['analyses']:
                    componente = analise.get('component', 'Desconhecido')
                    element_type = analise.get('element_type', 'Element')
                    stride_summary = analise.get('stride_summary', '')
                    
                    # Formato regra de ouro: Elemento (Tipo) → STRIDE: X, Y, Z
                    expander_title = f"📌 {componente} ({element_type}) → STRIDE: {stride_summary}"
                    
                    with st.expander(expander_title, expanded=False):
                        # Descrição
                        if 'description' in analise:
                            st.caption(analise['description'])
                        
                        # Notas positivas (controles de segurança)
                        if 'note' in analise:
                            st.info(analise['note'])
                        
                        # Riscos STRIDE
                        riscos = analise.get('risks') or analise.get('stride') or []
                        
                        if riscos:
                            for risco in riscos:
                                # Extrai campos (suporta diferentes formatos)
                                tipo = risco.get('type') or risco.get('threat') or "Risco"
                                threat_name = risco.get('threat', tipo)
                                detalhe = risco.get('detail') or risco.get('desc') or "Sem detalhes"
                                mitigacao = risco.get('mitigation') or risco.get('fix') or "Verificar documentação"
                                severidade = risco.get('severity', 'MEDIUM')
                                
                                severity_class = risk_color_map.get(severidade, 'risk-medium')
                                
                                st.markdown(f"""
                                **🔴 {threat_name}** <span class="{severity_class}">{severidade}</span>
                                
                                _{detalhe}_
                                
                                🛡️ **Mitigação:** `{mitigacao}`
                                """, unsafe_allow_html=True)
                                st.divider()
                        else:
                            st.write("✅ Sem riscos críticos mapeados para este componente.")
                
                # Exportar relatório
                st.divider()
                st.subheader("📥 Exportar Relatório")
                
                report_data = {
                    "summary": {
                        "total_components": arch_analysis['total_components'],
                        "risk_score": arch_analysis['risk_score'],
                        "risk_level": arch_analysis['risk_level'],
                        "total_risks": arch_analysis['total_risks'],
                        "security_controls": arch_analysis['security_controls']
                    },
                    "detections": detections,
                    "stride_analyses": arch_analysis['analyses']
                }
                
                st.download_button(
                    label="📄 Baixar Relatório JSON",
                    data=json.dumps(report_data, indent=2, ensure_ascii=False),
                    file_name="security_report.json",
                    mime="application/json"
                )

else:
    # Estado inicial - sem upload
    st.info("👆 Faça upload de um diagrama de arquitetura para começar a análise.")
    
    # Exemplos de uso
    with st.expander("💡 Dicas de Uso"):
        st.markdown("""
        ### Como obter melhores resultados:
        
        1. **Use diagramas com ícones oficiais** AWS/Azure
        2. **Resolução mínima recomendada:** 800x600 pixels
        3. **Evite diagramas muito complexos** - o modelo foi treinado em diagramas típicos
        4. **Ajuste o threshold** se componentes não forem detectados
        
        ### O que o sistema detecta (14 categorias STRIDE):
        
        | Categoria | Exemplos |
        |-----------|----------|
        | Compute | EC2, Lambda, EKS, Fargate, VM, SEI, SIP |
        | Database | RDS, DynamoDB, Aurora, Redis, Cosmos DB |
        | Storage | S3, EBS, EFS, Glacier, Blob Storage |
        | Network | VPC, Load Balancer, CloudFront, Route 53 |
        | Security | IAM, WAF, KMS, Cognito, GuardDuty |
        | API Gateway | API Gateway, AppSync, Apigee |
        | Messaging | SQS, SNS, SES, EventBridge, Kinesis |
        | Monitoring | CloudWatch, CloudTrail, X-Ray |
        | Identity | User, Client, Active Directory |
        | ML/AI | SageMaker, Rekognition, Vertex AI |
        | DevOps | CodePipeline, ECR, CloudFormation |
        | Serverless | Lambda, Step Functions, Cloud Functions |
        | Analytics | Athena, Glue, BigQuery, Redshift |
        | Other | Componentes não mapeados |
        """)