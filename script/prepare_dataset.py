"""
Script para preparar o dataset completo:
1. Extrai o dataset Kaggle original COMPLETO (kaggle_dataset_cache.zip)
2. Converte anotações labelme (JSON) → Pascal VOC (XML)
3. Adiciona suas anotações customizadas ao dataset
4. Cria um novo ZIP final para upload ao Drive
"""

import json
import os
import shutil
import zipfile
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom import minidom


def labelme_to_voc(json_path: Path, output_xml_path: Path):
    """Converte anotação labelme JSON para Pascal VOC XML."""
    
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Dimensões da imagem
    img_width = data.get('imageWidth', 0)
    img_height = data.get('imageHeight', 0)
    img_filename = data.get('imagePath', json_path.stem + '.png')
    
    # Cria estrutura XML
    annotation = Element('annotation')
    
    SubElement(annotation, 'folder').text = 'images'
    SubElement(annotation, 'filename').text = os.path.basename(img_filename)
    
    source = SubElement(annotation, 'source')
    SubElement(source, 'database').text = 'Custom Diagrams'
    
    size = SubElement(annotation, 'size')
    SubElement(size, 'width').text = str(img_width)
    SubElement(size, 'height').text = str(img_height)
    SubElement(size, 'depth').text = '3'
    
    SubElement(annotation, 'segmented').text = '0'
    
    # Processa cada shape (anotação)
    for shape in data.get('shapes', []):
        if shape['shape_type'] != 'rectangle':
            continue
            
        label = shape['label']
        points = shape['points']
        
        # labelme: [[x1, y1], [x2, y2]]
        x1, y1 = points[0]
        x2, y2 = points[1]
        
        # Garante ordem correta
        xmin = min(x1, x2)
        xmax = max(x1, x2)
        ymin = min(y1, y2)
        ymax = max(y1, y2)
        
        obj = SubElement(annotation, 'object')
        SubElement(obj, 'name').text = label
        SubElement(obj, 'pose').text = 'Unspecified'
        SubElement(obj, 'truncated').text = '0'
        SubElement(obj, 'difficult').text = '0'
        
        bndbox = SubElement(obj, 'bndbox')
        SubElement(bndbox, 'xmin').text = str(int(xmin))
        SubElement(bndbox, 'ymin').text = str(int(ymin))
        SubElement(bndbox, 'xmax').text = str(int(xmax))
        SubElement(bndbox, 'ymax').text = str(int(ymax))
    
    # Formata XML
    xml_str = minidom.parseString(tostring(annotation)).toprettyxml(indent='  ')
    
    # Remove declaração XML duplicada
    xml_lines = xml_str.split('\n')[1:]  # Pula primeira linha (<?xml...?>)
    xml_str = '\n'.join(xml_lines)
    
    with open(output_xml_path, 'w', encoding='utf-8') as f:
        f.write(xml_str)
    
    return len(data.get('shapes', []))


def main():
    BASE_DIR = Path(__file__).parent
    DIAGRAM_DIR = BASE_DIR / "diagram"
    KAGGLE_ZIP = BASE_DIR / "kaggle_dataset_cache" / "kaggle_dataset_cache.zip"
    OUTPUT_DIR = BASE_DIR / "dataset_final"
    OUTPUT_ZIP = BASE_DIR / "dataset_ready.zip"
    
    print("=" * 60)
    print("🚀 PREPARAÇÃO DO DATASET PARA TREINAMENTO")
    print("=" * 60)
    
    # Limpa output anterior
    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(exist_ok=True)
    
    total_images = 0
    custom_annotations = 0
    
    # =========================================================
    # 1. Extrai dataset Kaggle COMPLETO (sem filtrar nada)
    # =========================================================
    print("\n📦 Extraindo dataset Kaggle original COMPLETO...")
    
    if not KAGGLE_ZIP.exists():
        print(f"   ❌ ZIP não encontrado: {KAGGLE_ZIP}")
        print("   Por favor, baixe o dataset do Kaggle primeiro.")
        return
    
    # Abre ZIP e extrai TUDO
    with zipfile.ZipFile(KAGGLE_ZIP, 'r') as zf:
        all_entries = zf.namelist()
        
        # Filtra: pega apenas arquivos (não pastas) que são .png/.jpg/.xml
        valid_extensions = ('.png', '.jpg', '.jpeg', '.xml', '.PNG', '.JPG', '.JPEG', '.XML')
        
        files_to_extract = [
            f for f in all_entries 
            if f.endswith(valid_extensions) 
            and not f.endswith('/')
        ]
        
        print(f"   📊 Total no ZIP: {len(all_entries)} itens")
        print(f"   📊 Arquivos válidos: {len(files_to_extract)} arquivos")
        
        # Extrai todos os arquivos
        print("   📂 Extraindo arquivos...")
        extracted = 0
        for file_path in files_to_extract:
            try:
                # Lê conteúdo
                content = zf.read(file_path)
                
                # Salva com nome simples (sem caminho de pasta)
                filename = os.path.basename(file_path)
                dest_path = OUTPUT_DIR / filename
                
                # Se já existe, adiciona sufixo para não sobrescrever
                if dest_path.exists():
                    base, ext = os.path.splitext(filename)
                    counter = 1
                    while dest_path.exists():
                        dest_path = OUTPUT_DIR / f"{base}_{counter}{ext}"
                        counter += 1
                
                with open(dest_path, 'wb') as f:
                    f.write(content)
                
                extracted += 1
                if extracted % 2000 == 0:
                    print(f"      {extracted} arquivos...")
            except Exception as e:
                pass  # Ignora erros silenciosamente
        
        print(f"   ✅ Extraídos: {extracted} arquivos")
        
        # Conta imagens e XMLs
        kaggle_images = len([f for f in OUTPUT_DIR.iterdir() if f.suffix.lower() in ('.png', '.jpg', '.jpeg')])
        kaggle_xmls = len([f for f in OUTPUT_DIR.iterdir() if f.suffix.lower() == '.xml'])
        print(f"   📊 Kaggle: {kaggle_images} imagens, {kaggle_xmls} XMLs")
        total_images += kaggle_images
    
    # =========================================================
    # 2. Adiciona anotações customizadas (labelme JSON → XML)
    # =========================================================
    print("\n🔄 Adicionando anotações customizadas (diagram/)...")
    
    if not DIAGRAM_DIR.exists():
        print(f"   ⚠️ Pasta diagram/ não encontrada")
    else:
        json_files = list(DIAGRAM_DIR.glob("*.json"))
        
        if not json_files:
            print("   ⚠️ Nenhum arquivo JSON encontrado em diagram/")
        else:
            for json_file in json_files:
                # Encontra imagem correspondente
                img_name = json_file.stem
                img_file = None
                for ext in ['.png', '.jpg', '.jpeg', '.PNG', '.JPG', '.JPEG']:
                    candidate = DIAGRAM_DIR / f"{img_name}{ext}"
                    if candidate.exists():
                        img_file = candidate
                        break
                
                if not img_file:
                    print(f"   ⚠️ Imagem não encontrada para {json_file.name}")
                    continue
                
                # Converte JSON → XML
                xml_output = OUTPUT_DIR / f"{img_name}.xml"
                n_annotations = labelme_to_voc(json_file, xml_output)
                
                # Copia imagem
                shutil.copy(img_file, OUTPUT_DIR / img_file.name)
                
                print(f"   ✅ {img_name}: {n_annotations} anotações")
                total_images += 1
                custom_annotations += n_annotations
    
    # =========================================================
    # 3. Cria ZIP final
    # =========================================================
    print(f"\n📦 Criando ZIP final...")
    
    # Conta arquivos finais
    final_files = list(OUTPUT_DIR.iterdir())
    final_images = [f for f in final_files if f.suffix.lower() in ('.png', '.jpg', '.jpeg')]
    final_xmls = [f for f in final_files if f.suffix.lower() == '.xml']
    
    print(f"   📊 Total: {len(final_images)} imagens, {len(final_xmls)} XMLs")
    
    # Cria ZIP
    if OUTPUT_ZIP.exists():
        OUTPUT_ZIP.unlink()
    
    print("   📦 Compactando (isso pode demorar alguns minutos)...")
    with zipfile.ZipFile(OUTPUT_ZIP, 'w', zipfile.ZIP_DEFLATED) as zf:
        for i, file in enumerate(final_files):
            zf.write(file, file.name)
            if (i + 1) % 2000 == 0:
                print(f"      {i + 1} arquivos...")
    
    # Tamanho do ZIP
    zip_size_mb = OUTPUT_ZIP.stat().st_size / (1024 * 1024)
    zip_size_gb = zip_size_mb / 1024
    
    print(f"\n" + "=" * 60)
    print("✅ DATASET PRONTO!")
    print("=" * 60)
    print(f"\n📁 ZIP criado: {OUTPUT_ZIP}")
    if zip_size_gb >= 1:
        print(f"📊 Tamanho: {zip_size_gb:.2f} GB")
    else:
        print(f"📊 Tamanho: {zip_size_mb:.1f} MB")
    print(f"📊 Imagens: {len(final_images)} (Kaggle + suas {custom_annotations} anotações customizadas)")
    print(f"\n📋 Próximos passos:")
    print(f"   1. Faça upload de 'dataset_ready.zip' para o Google Drive")
    print(f"   2. Coloque em: My Drive/colab/cloud-arch-security-mvp/")
    print(f"   3. Execute o notebook no Colab")
    
    # Limpeza opcional
    print(f"\n🗑️ Para limpar a pasta temporária, execute:")
    print(f'   Remove-Item -Recurse -Force "{OUTPUT_DIR}"')


if __name__ == "__main__":
    main()
