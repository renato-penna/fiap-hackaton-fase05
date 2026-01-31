"""
Script de Análise do Dataset YOLO
=================================

Este script analisa a distribuição de classes no dataset e gera
estatísticas úteis para entender o desbalanceamento.

Uso:
    python analyze_dataset.py
"""

import os
import yaml
from collections import Counter
from pathlib import Path
import sys


def load_class_names(data_yaml_path: str) -> list:
    """Carrega os nomes das classes do data.yaml."""
    with open(data_yaml_path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    return data.get('names', [])


def count_classes_in_labels(labels_path: Path) -> Counter:
    """Conta ocorrências de cada classe nos arquivos de labels."""
    class_counts = Counter()
    
    if not labels_path.exists():
        return class_counts
    
    for label_file in labels_path.glob("*.txt"):
        with open(label_file, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if parts:
                    try:
                        class_id = int(parts[0])
                        class_counts[class_id] += 1
                    except ValueError:
                        continue
    
    return class_counts


def analyze_dataset(dataset_path: str):
    """Analisa o dataset completo e exibe estatísticas."""
    dataset_path = Path(dataset_path)
    data_yaml_path = dataset_path / "data.yaml"
    
    if not data_yaml_path.exists():
        print(f"❌ Arquivo data.yaml não encontrado em: {data_yaml_path}")
        return
    
    # Carrega nomes das classes
    class_names = load_class_names(data_yaml_path)
    print(f"\n📊 ANÁLISE DO DATASET: {dataset_path}")
    print(f"{'='*60}")
    print(f"Total de classes definidas: {len(class_names)}")
    
    # Conta classes em cada split
    splits = ['train', 'valid', 'test']
    all_counts = Counter()
    split_stats = {}
    
    for split in splits:
        labels_path = dataset_path / split / "labels"
        counts = count_classes_in_labels(labels_path)
        all_counts.update(counts)
        
        total_annotations = sum(counts.values())
        total_files = len(list(labels_path.glob("*.txt"))) if labels_path.exists() else 0
        
        split_stats[split] = {
            'files': total_files,
            'annotations': total_annotations,
            'counts': counts
        }
        
        print(f"\n📁 {split.upper()}:")
        print(f"   Arquivos: {total_files}")
        print(f"   Anotações: {total_annotations}")
    
    # Estatísticas gerais
    total_annotations = sum(all_counts.values())
    classes_with_samples = len([c for c in all_counts.values() if c > 0])
    
    print(f"\n{'='*60}")
    print(f"📈 ESTATÍSTICAS GERAIS:")
    print(f"   Total de anotações: {total_annotations}")
    print(f"   Classes com amostras: {classes_with_samples}/{len(class_names)}")
    
    # Top 20 classes mais frequentes
    print(f"\n🏆 TOP 20 CLASSES MAIS FREQUENTES:")
    print(f"{'Rank':<5} {'ID':<5} {'Nome':<35} {'Count':<8} {'%':<8}")
    print("-" * 65)
    
    for rank, (class_id, count) in enumerate(all_counts.most_common(20), 1):
        name = class_names[class_id] if class_id < len(class_names) else f"ID_{class_id}"
        percentage = (count / total_annotations * 100) if total_annotations > 0 else 0
        print(f"{rank:<5} {class_id:<5} {name:<35} {count:<8} {percentage:.2f}%")
    
    # Classes com poucas amostras
    MIN_SAMPLES = 10
    rare_classes = [(cid, cnt) for cid, cnt in all_counts.items() if cnt < MIN_SAMPLES]
    
    print(f"\n⚠️ CLASSES COM MENOS DE {MIN_SAMPLES} AMOSTRAS: {len(rare_classes)}")
    if rare_classes:
        print(f"{'ID':<5} {'Nome':<35} {'Count':<8}")
        print("-" * 50)
        for class_id, count in sorted(rare_classes, key=lambda x: x[1]):
            name = class_names[class_id] if class_id < len(class_names) else f"ID_{class_id}"
            print(f"{class_id:<5} {name:<35} {count:<8}")
    
    # Verifica classe "groups" especificamente
    groups_id = None
    for i, name in enumerate(class_names):
        if name.lower() == 'groups':
            groups_id = i
            break
    
    if groups_id is not None:
        groups_count = all_counts.get(groups_id, 0)
        groups_pct = (groups_count / total_annotations * 100) if total_annotations > 0 else 0
        print(f"\n🎯 CLASSE 'groups' (ID {groups_id}):")
        print(f"   Contagem: {groups_count}")
        print(f"   Proporção: {groups_pct:.2f}%")
        
        if groups_pct > 20:
            print("   ⚠️ ALERTA: Proporção alta pode causar viés no modelo!")
        else:
            print("   ✅ Proporção dentro do esperado")
    
    # Análise de desbalanceamento
    if all_counts:
        max_count = max(all_counts.values())
        min_count = min(all_counts.values())
        ratio = max_count / min_count if min_count > 0 else float('inf')
        
        print(f"\n📊 ANÁLISE DE DESBALANCEAMENTO:")
        print(f"   Classe mais frequente: {max_count} amostras")
        print(f"   Classe menos frequente: {min_count} amostras")
        print(f"   Ratio max/min: {ratio:.1f}x")
        
        if ratio > 100:
            print("   ⚠️ ALERTA: Desbalanceamento SEVERO detectado!")
            print("   💡 Recomendação: Usar class weights ou agrupar classes raras")
        elif ratio > 20:
            print("   ⚠️ Desbalanceamento MODERADO detectado")
            print("   💡 Recomendação: Aumentar data augmentation")
        else:
            print("   ✅ Dataset relativamente balanceado")
    
    print(f"\n{'='*60}")
    print("Análise concluída!")


if __name__ == "__main__":
    # Define o caminho do dataset
    script_dir = Path(__file__).parent
    dataset_path = script_dir.parent / "dataset"
    
    if len(sys.argv) > 1:
        dataset_path = Path(sys.argv[1])
    
    analyze_dataset(dataset_path)
