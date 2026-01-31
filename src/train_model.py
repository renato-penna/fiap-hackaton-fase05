from ultralytics import YOLO
import os

def main():
    # Define o caminho absoluto para o data.yaml
    data_path = os.path.abspath('../dataset/data.yaml')
    
    # Verifica se o data.yaml existe
    if not os.path.exists(data_path):
        print(f"ERRO: O arquivo 'data.yaml' não foi encontrado em: {data_path}")
        return

    # Detecta automaticamente se há GPU disponível
    try:
        import torch
        device = '0' if torch.cuda.is_available() else 'cpu'
        print(f"Usando dispositivo: {'GPU' if device == '0' else 'CPU'}")
    except ImportError:
        device = 'cpu'
        print("PyTorch não encontrado, usando CPU")

    # 1. Carrega o modelo Nano (mais leve e rápido para MVP)
    print("Carregando modelo YOLOv11n...")
    model = YOLO('../models/yolo11n.pt') 

    # 2. Inicia o treinamento
    print("Iniciando treinamento...")
    results = model.train(
        data=data_path,    # O arquivo que mapeia seu dataset
        epochs=30,           # 30 épocas é suficiente para um MVP rápido
        imgsz=416,           # Tamanho menor para economizar memória GPU
        batch=2,             # Batch muito pequeno para MX250 (2GB VRAM)
        name='mvp_security', # Nome da pasta onde salvará o resultado
        device=device        # Detecta automaticamente GPU ou CPU
    )

    print(f"Treinamento concluído! O modelo foi salvo em: runs/detect/mvp_security/weights/best.pt")

if __name__ == '__main__':
    main()