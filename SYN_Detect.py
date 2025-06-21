#!/usr/bin/env python3
"""
Detector de SYN Flooding usando Autômatos Determinísticos Finitos com Scapy
Este programa monitora tráfego TCP real e detecta padrões suspeitos de SYN Flood
"""

import time
import threading
from collections import defaultdict, deque
from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional
import argparse
import signal
import sys

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
except ImportError:
    print("❌ Erro: Scapy não está instalado!")
    print("💡 Instale com: pip install scapy")
    sys.exit(1)

class TCPState(Enum):
    """Estados do protocolo TCP"""
    CLOSED = "CLOSED"
    LISTEN = "LISTEN"
    SYN_SENT = "SYN_SENT"
    SYN_RECEIVED = "SYN_RECEIVED"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT_1 = "FIN_WAIT_1"
    FIN_WAIT_2 = "FIN_WAIT_2"
    CLOSE_WAIT = "CLOSE_WAIT"
    CLOSING = "CLOSING"
    LAST_ACK = "LAST_ACK"
    TIME_WAIT = "TIME_WAIT"

class PacketFlags(Enum):
    """Flags dos pacotes TCP"""
    SYN = "SYN"
    SYN_ACK = "SYN_ACK"
    ACK = "ACK"
    FIN = "FIN"
    RST = "RST"
    PSH = "PSH"
    URG = "URG"

@dataclass
class ConnectionInfo:
    """Informações de uma conexão TCP"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    state: TCPState
    syn_count: int
    last_update: float
    flags_sequence: List[str]

class SYNFloodDetectorFSM:
    """
    Detector de SYN Flooding usando Autômato Determinístico Finito com Scapy
    """
    
    def __init__(self, interface=None, syn_threshold=100, time_window=10, 
                 connection_timeout=30, verbose=False):
        # Configurações
        self.interface = interface
        self.syn_threshold = syn_threshold
        self.time_window = time_window
        self.connection_timeout = connection_timeout
        self.verbose = verbose
        
        # Estruturas de dados
        self.connections: Dict[str, ConnectionInfo] = {}
        self.syn_counts: Dict[str, deque] = defaultdict(deque)
        self.blocked_ips: set = set()
        
        # Estatísticas
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'syn_packets': 0,
            'syn_ack_packets': 0,
            'established_connections': 0,
            'alerts_generated': 0,
            'unique_ips': set(),
            'start_time': time.time()
        }
        
        # Alertas
        self.alerts = []
        self.alert_callbacks = []
        
        # Controle de threads
        self.running = False
        self.cleanup_thread = None
        
        # Transições do autômato TCP
        self.tcp_transitions = {
            # Estado inicial -> Estados possíveis
            (TCPState.CLOSED, PacketFlags.SYN): TCPState.SYN_RECEIVED,
            (TCPState.LISTEN, PacketFlags.SYN): TCPState.SYN_RECEIVED,
            (TCPState.SYN_SENT, PacketFlags.SYN_ACK): TCPState.ESTABLISHED,
            (TCPState.SYN_RECEIVED, PacketFlags.ACK): TCPState.ESTABLISHED,
            (TCPState.ESTABLISHED, PacketFlags.FIN): TCPState.FIN_WAIT_1,
            (TCPState.ESTABLISHED, PacketFlags.RST): TCPState.CLOSED,
            (TCPState.FIN_WAIT_1, PacketFlags.ACK): TCPState.FIN_WAIT_2,
            (TCPState.FIN_WAIT_2, PacketFlags.FIN): TCPState.TIME_WAIT,
            (TCPState.TIME_WAIT, PacketFlags.ACK): TCPState.CLOSED,
        }
        
        print(f"🛡️  Detector SYN Flood inicializado")
        print(f"   Interface: {interface or 'Auto-detectar'}")
        print(f"   Threshold SYN: {syn_threshold}")
        print(f"   Janela de tempo: {time_window}s")
    
    def _get_packet_flags(self, tcp_layer) -> PacketFlags:
        """Identifica as flags do pacote TCP"""
        if tcp_layer.flags & 0x02 and tcp_layer.flags & 0x10:  # SYN + ACK
            return PacketFlags.SYN_ACK
        elif tcp_layer.flags & 0x02:  # SYN
            return PacketFlags.SYN
        elif tcp_layer.flags & 0x10:  # ACK
            return PacketFlags.ACK
        elif tcp_layer.flags & 0x01:  # FIN
            return PacketFlags.FIN
        elif tcp_layer.flags & 0x04:  # RST
            return PacketFlags.RST
        elif tcp_layer.flags & 0x08:  # PSH
            return PacketFlags.PSH
        elif tcp_layer.flags & 0x20:  # URG
            return PacketFlags.URG
        else:
            return PacketFlags.ACK  # Default
    
    def _get_connection_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> str:
        """Gera chave única para identificar conexão"""
        return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
    
    def _process_tcp_packet(self, packet):
        """Processa pacote TCP através do autômato finito"""
        try:
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]
            
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            timestamp = time.time()
            
            # Atualiza estatísticas
            self.stats['tcp_packets'] += 1
            self.stats['unique_ips'].add(src_ip)
            
            # Identifica flags do pacote
            packet_flags = self._get_packet_flags(tcp_layer)
            
            # Processa pacotes SYN
            if packet_flags == PacketFlags.SYN:
                self.stats['syn_packets'] += 1
                self._process_syn_packet(src_ip, dst_ip, src_port, dst_port, timestamp)
            elif packet_flags == PacketFlags.SYN_ACK:
                self.stats['syn_ack_packets'] += 1
            
            # Gerencia estado da conexão
            conn_key = self._get_connection_key(src_ip, dst_ip, src_port, dst_port)
            reverse_key = self._get_connection_key(dst_ip, src_ip, dst_port, src_port)
            
            # Busca conexão existente
            connection = self.connections.get(conn_key) or self.connections.get(reverse_key)
            
            if not connection:
                # Nova conexão
                connection = ConnectionInfo(
                    src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
                    state=TCPState.CLOSED, syn_count=0, last_update=timestamp,
                    flags_sequence=[]
                )
                self.connections[conn_key] = connection
            
            # Atualiza estado usando autômato
            old_state = connection.state
            transition_key = (old_state, packet_flags)
            
            if transition_key in self.tcp_transitions:
                connection.state = self.tcp_transitions[transition_key]
                connection.last_update = timestamp
                connection.flags_sequence.append(packet_flags.value)
                
                # Conta estabelecimento de conexões
                if connection.state == TCPState.ESTABLISHED and old_state != TCPState.ESTABLISHED:
                    self.stats['established_connections'] += 1
                
                if self.verbose:
                    print(f"🔄 {src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
                          f"{old_state.value} -> {connection.state.value} | {packet_flags.value}")
            
        except Exception as e:
            if self.verbose:
                print(f"❌ Erro processando pacote: {e}")
    
    def _process_syn_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, timestamp: float):
        """Processa especificamente pacotes SYN para detecção de flood"""
        # Atualiza contador de SYNs por IP
        syn_times = self.syn_counts[src_ip]
        syn_times.append(timestamp)
        
        # Remove timestamps antigos
        cutoff_time = timestamp - self.time_window
        while syn_times and syn_times[0] < cutoff_time:
            syn_times.popleft()
        
        # Verifica se excedeu threshold
        syn_count = len(syn_times)
        if syn_count > self.syn_threshold:
            self._generate_alert(src_ip, dst_ip, syn_count, timestamp)
    
    def _generate_alert(self, src_ip: str, dst_ip: str, syn_count: int, timestamp: float):
        """Gera alerta de possível SYN Flood"""
        severity = "CRITICAL" if syn_count > self.syn_threshold * 3 else \
                  "HIGH" if syn_count > self.syn_threshold * 2 else "MEDIUM"
        
        alert = {
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'syn_count': syn_count,
            'threshold': self.syn_threshold,
            'time_window': self.time_window,
            'severity': severity,
            'blocked': src_ip in self.blocked_ips
        }
        
        self.alerts.append(alert)
        self.stats['alerts_generated'] += 1
        
        # Auto-block IPs críticos
        if severity == "CRITICAL" and src_ip not in self.blocked_ips:
            self.blocked_ips.add(src_ip)
            alert['blocked'] = True
        
        # Exibe alerta
        print(f"\n🚨 ALERTA SYN FLOOD - {severity}")
        print(f"   Origem: {src_ip} -> Destino: {dst_ip}")
        print(f"   Pacotes SYN: {syn_count} em {self.time_window}s (limite: {self.syn_threshold})")
        print(f"   Timestamp: {time.ctime(timestamp)}")
        if alert['blocked']:
            print(f"   Status: IP BLOQUEADO AUTOMATICAMENTE")
        print("-" * 60)
        
        # Chama callbacks personalizados
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f"❌ Erro em callback: {e}")
    
    def _packet_handler(self, packet):
        """Handler principal para captura de pacotes"""
        self.stats['total_packets'] += 1
        
        # Processa apenas pacotes TCP
        if packet.haslayer(TCP):
            self._process_tcp_packet(packet)
    
    def _cleanup_worker(self):
        """Thread para limpeza periódica"""
        while self.running:
            current_time = time.time()
            
            # Remove conexões antigas
            expired_connections = []
            for key, conn in self.connections.items():
                if current_time - conn.last_update > self.connection_timeout:
                    expired_connections.append(key)
            
            for key in expired_connections:
                del self.connections[key]
            
            # Remove contadores SYN antigos
            for ip in list(self.syn_counts.keys()):
                syn_times = self.syn_counts[ip]
                cutoff_time = current_time - self.time_window
                while syn_times and syn_times[0] < cutoff_time:
                    syn_times.popleft()
                if not syn_times:
                    del self.syn_counts[ip]
            
            time.sleep(10)  # Limpeza a cada 10 segundos
    
    def add_alert_callback(self, callback):
        """Adiciona callback personalizado para alertas"""
        self.alert_callbacks.append(callback)
    
    def start_monitoring(self):
        """Inicia monitoramento de rede"""
        self.running = True
        
        # Inicia thread de limpeza
        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        self.cleanup_thread.start()
        
        print(f"🔍 Iniciando captura de pacotes...")
        print(f"   Pressione Ctrl+C para parar")
        print("-" * 60)
        
        try:
            # Filtra apenas tráfego TCP
            sniff(iface=self.interface, filter="tcp", prn=self._packet_handler, store=0)
        except KeyboardInterrupt:
            print("\n⏹️  Captura interrompida pelo usuário")
        except Exception as e:
            print(f"❌ Erro na captura: {e}")
        finally:
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Para o monitoramento"""
        self.running = False
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=5)
        print("✅ Monitoramento finalizado")
    
    def print_statistics(self):
        """Exibe estatísticas detalhadas"""
        runtime = time.time() - self.stats['start_time']
        
        print("\n📊 ESTATÍSTICAS DO DETECTOR")
        print("=" * 50)
        print(f"Tempo de execução: {runtime:.1f}s")
        print(f"Total de pacotes: {self.stats['total_packets']}")
        print(f"Pacotes TCP: {self.stats['tcp_packets']}")
        print(f"Pacotes SYN: {self.stats['syn_packets']}")
        print(f"Pacotes SYN-ACK: {self.stats['syn_ack_packets']}")
        print(f"Conexões estabelecidas: {self.stats['established_connections']}")
        print(f"IPs únicos: {len(self.stats['unique_ips'])}")
        print(f"Conexões ativas: {len(self.connections)}")
        print(f"Alertas gerados: {self.stats['alerts_generated']}")
        print(f"IPs bloqueados: {len(self.blocked_ips)}")
        
        if self.stats['syn_packets'] > 0 and self.stats['established_connections'] > 0:
            ratio = self.stats['syn_packets'] / self.stats['established_connections']
            print(f"Ratio SYN/Estabelecidas: {ratio:.2f}")
        
        print("=" * 50)
        
        # Mostra últimos alertas
        if self.alerts:
            print("\n🚨 ÚLTIMOS ALERTAS:")
            for alert in self.alerts[-3:]:
                print(f"   {alert['severity']}: {alert['src_ip']} "
                      f"({alert['syn_count']} SYNs) - {time.ctime(alert['timestamp'])}")
    
    def get_blocked_ips(self) -> List[str]:
        """Retorna lista de IPs bloqueados"""
        return list(self.blocked_ips)
    
    def unblock_ip(self, ip: str) -> bool:
        """Remove IP da lista de bloqueados"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            print(f"✅ IP {ip} desbloqueado")
            return True
        return False

def custom_alert_handler(alert):
    """Exemplo de handler personalizado para alertas"""
    if alert['severity'] == 'CRITICAL':
        # Aqui você poderia integrar com sistemas externos
        # como firewalls, SIEM, notificações, etc.
        print(f"🔥 Handler personalizado: Alerta crítico de {alert['src_ip']}")

def signal_handler(sig, frame):
    """Handler para sinais do sistema"""
    print('\n⏹️  Finalizando detector...')
    sys.exit(0)

def main():
    """Função principal"""
    parser = argparse.ArgumentParser(description='Detector SYN Flood com Autômatos Finitos')
    parser.add_argument('-i', '--interface', help='Interface de rede (ex: eth0, wlan0)')
    parser.add_argument('-t', '--threshold', type=int, default=50, 
                       help='Threshold de pacotes SYN (padrão: 50)')
    parser.add_argument('-w', '--window', type=int, default=10,
                       help='Janela de tempo em segundos (padrão: 10)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Modo verboso')
    parser.add_argument('--timeout', type=int, default=60,
                       help='Timeout de conexão em segundos (padrão: 60)')
    
    args = parser.parse_args()
    
    # Configura handler para Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    print("🛡️  Detector de SYN Flooding com Scapy")
    print("=" * 60)
    
    # Verifica privilégios
    if os.geteuid() != 0:
        print("⚠️  Aviso: Execute como root para melhor captura de pacotes")
    
    # Cria detector
    detector = SYNFloodDetectorFSM(
        interface=args.interface,
        syn_threshold=args.threshold,
        time_window=args.window,
        connection_timeout=args.timeout,
        verbose=args.verbose
    )
    
    # Adiciona handler personalizado
    detector.add_alert_callback(custom_alert_handler)
    
    try:
        # Inicia monitoramento
        detector.start_monitoring()
        
    except Exception as e:
        print(f"❌ Erro: {e}")
    
    finally:
        # Mostra estatísticas finais
        detector.print_statistics()

if __name__ == "__main__":
    main()