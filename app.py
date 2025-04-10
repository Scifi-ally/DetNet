from flask import Flask
from flask_socketio import SocketIO, emit
from scapy.all import *
import sqlite3
import threading
import numpy as np
from datetime import datetime
import random
from collections import defaultdict

app = Flask(__name__, static_folder='static', static_url_path='')
socketio = SocketIO(app, cors_allowed_origins="*")

sniffing = False
sniff_thread = None
attack_active = False
current_attack = None
packet_history = []
MAX_HISTORY = 100
attack_thresholds = {
    'DDoS': 50,
    'PortScan': 10,
    'SQLInjection': 5,
    'XSS': 5,
    'Malware': 20
}
port_counts = defaultdict(int)
last_check = datetime.now()
historical_sizes = []

def init_db():
    conn = sqlite3.connect('ids_data.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS packets 
                (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source_ip TEXT, 
                 dest_ip TEXT, packet_size INTEGER, protocol TEXT, is_malicious INTEGER)''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON packets(timestamp)')
    conn.commit()
    conn.close()

def random_ip():
    return '.'.join(str(random.randint(0, 255)) for _ in range(4))

def detect_anomaly(packet_size, historical_data):
    if len(historical_data) < 10:
        return False
    mean = np.mean(historical_data)
    std = np.std(historical_data)
    return abs((packet_size - mean) / std) > 2.5

def detect_attack(packets):
    global port_counts, last_check
    current_time = datetime.now()
    time_diff = (current_time - last_check).total_seconds()
    if time_diff < 1:
        return None
    if time_diff >= 1:
        port_counts.clear()
        last_check = current_time
    packet_count = len(packets)
    ddos_count = sum(1 for p in packets if p['packet_size'] > 1000)
    port_scan_count = len(set(p['dest_port'] for p in packets if 'dest_port' in p))
    sql_injection_count = sum(1 for p in packets if 200 <= p['packet_size'] <= 1000 and p['is_malicious'])
    xss_count = sum(1 for p in packets if 300 <= p['packet_size'] <= 1500 and p['is_malicious'])
    malware_count = sum(1 for p in packets if 500 <= p['packet_size'] <= 3000)
    if packet_count / time_diff > attack_thresholds['DDoS'] and ddos_count / time_diff > 0.5 * packet_count / time_diff:
        return 'DDoS'
    elif port_scan_count / time_diff > attack_thresholds['PortScan']:
        return 'PortScan'
    elif sql_injection_count / time_diff > attack_thresholds['SQLInjection']:
        return 'SQLInjection'
    elif xss_count / time_diff > attack_thresholds['XSS']:
        return 'XSS'
    elif malware_count / time_diff > attack_thresholds['Malware']:
        return 'Malware'
    return None

def monitor_network():
    global sniffing, packet_history, historical_sizes, current_attack
    while sniffing:
        def packet_handler(packet):
            global packet_history, historical_sizes, current_attack
            if IP in packet and sniffing:
                try:
                    dest_port = packet[IP].dport if TCP in packet or UDP in packet else 0
                    pkt_info = {
                        'timestamp': datetime.now().isoformat(),
                        'source_ip': packet[IP].src,
                        'dest_ip': packet[IP].dst,
                        'packet_size': len(packet),
                        'protocol': packet[IP].proto,
                        'dest_port': dest_port,
                        'is_malicious': 0
                    }
                    historical_sizes.append(pkt_info['packet_size'])
                    if len(historical_sizes) > MAX_HISTORY:
                        historical_sizes.pop(0)
                    if detect_anomaly(pkt_info['packet_size'], historical_sizes):
                        pkt_info['is_malicious'] = 1
                    packet_history.append(pkt_info)
                    if len(packet_history) > MAX_HISTORY:
                        packet_history.pop(0)
                    attack = detect_attack(packet_history[-50:])
                    if attack and attack != current_attack:
                        current_attack = attack
                        socketio.emit('attack_highlight', {'attack': current_attack})
                    elif not attack and current_attack:
                        socketio.emit('attack_highlight', {'attack': None})
                        current_attack = None
                    conn = sqlite3.connect('ids_data.db')
                    c = conn.cursor()
                    c.execute('INSERT INTO packets (timestamp, source_ip, dest_ip, packet_size, protocol, is_malicious) VALUES (?, ?, ?, ?, ?, ?)',
                             (pkt_info['timestamp'], pkt_info['source_ip'], pkt_info['dest_ip'],
                              pkt_info['packet_size'], pkt_info['protocol'], pkt_info['is_malicious']))
                    conn.commit()
                    conn.close()
                    socketio.emit('new_packet', pkt_info)
                except Exception as e:
                    print(f"Error processing packet: {e}")
        sniff(prn=packet_handler, store=0, timeout=1)

@app.route('/')
def index():
    return app.send_static_file('dashboard.html')

@socketio.on('start_monitoring')
def start_monitoring():
    global sniffing, sniff_thread, packet_history, historical_sizes, last_check
    if not sniffing:
        sniffing = True
        packet_history = []
        historical_sizes = []
        last_check = datetime.now()
        sniff_thread = threading.Thread(target=monitor_network, daemon=True)
        sniff_thread.start()
        emit('status_update', {'status': 'Online'})

@socketio.on('stop_monitoring')
def stop_monitoring():
    global sniffing, current_attack, attack_active
    sniffing = False
    attack_active = False
    if current_attack:
        socketio.emit('attack_highlight', {'attack': None})
        current_attack = None
    emit('status_update', {'status': 'Offline'})

@socketio.on('simulate_attack')
def simulate_attack(attack_type):
    global attack_active, current_attack
    if attack_active:
        emit('status_update', {'status': f'Another attack ({current_attack}) is already active'})
        return
    if attack_type not in ['DDoS', 'PortScan', 'SQLInjection', 'XSS', 'Malware']:
        emit('status_update', {'status': 'Invalid attack type'})
        return
    attack_active = True
    current_attack = attack_type
    socketio.emit('attack_highlight', {'attack': current_attack})
    def attack_thread():
        global attack_active, current_attack
        attack_duration = 5
        attack_ips = [random_ip() for _ in range(5)]
        start_time = datetime.now()
        while (datetime.now() - start_time).total_seconds() < attack_duration and attack_active:
            source_ip = random.choice(attack_ips)
            if attack_type == 'DDoS':
                pkt_info = {
                    'timestamp': datetime.now().isoformat(),
                    'source_ip': source_ip,
                    'dest_ip': random_ip(),
                    'packet_size': random.randint(1000, 5000),
                    'protocol': attack_type,
                    'dest_port': random.randint(1, 65535),
                    'is_malicious': 1
                }
                socketio.sleep(0.1)
            elif attack_type == 'PortScan':
                pkt_info = {
                    'timestamp': datetime.now().isoformat(),
                    'source_ip': source_ip,
                    'dest_ip': random_ip(),
                    'packet_size': random.randint(64, 128),
                    'protocol': attack_type,
                    'dest_port': random.randint(1, 65535),
                    'is_malicious': 1
                }
                socketio.sleep(0.5)
            elif attack_type == 'SQLInjection':
                pkt_info = {
                    'timestamp': datetime.now().isoformat(),
                    'source_ip': source_ip,
                    'dest_ip': random_ip(),
                    'packet_size': random.randint(200, 1000),
                    'protocol': attack_type,
                    'dest_port': 80,
                    'is_malicious': 1
                }
                socketio.sleep(0.3)
            elif attack_type == 'XSS':
                pkt_info = {
                    'timestamp': datetime.now().isoformat(),
                    'source_ip': source_ip,
                    'dest_ip': random_ip(),
                    'packet_size': random.randint(300, 1500),
                    'protocol': attack_type,
                    'dest_port': 80,
                    'is_malicious': 1
                }
                socketio.sleep(0.4)
            elif attack_type == 'Malware':
                pkt_info = {
                    'timestamp': datetime.now().isoformat(),
                    'source_ip': source_ip,
                    'dest_ip': random_ip(),
                    'packet_size': random.randint(500, 3000),
                    'protocol': attack_type,
                    'dest_port': random.randint(1, 65535),
                    'is_malicious': 1
                }
                socketio.sleep(0.2)
            conn = sqlite3.connect('ids_data.db')
            c = conn.cursor()
            c.execute('INSERT INTO packets (timestamp, source_ip, dest_ip, packet_size, protocol, is_malicious) VALUES (?, ?, ?, ?, ?, ?)',
                     (pkt_info['timestamp'], pkt_info['source_ip'], pkt_info['dest_ip'],
                      pkt_info['packet_size'], pkt_info['protocol'], pkt_info['is_malicious']))
            conn.commit()
            conn.close()
            socketio.emit('new_packet', pkt_info)
        socketio.emit('status_update', {'status': f'{attack_type} Attack Ended'})
        socketio.emit('attack_highlight', {'attack': None})
        attack_active = False
        current_attack = None
    threading.Thread(target=attack_thread, daemon=True).start()

@socketio.on('stop_attack')
def stop_attack():
    global attack_active, current_attack
    if attack_active:
        attack_active = False
        if current_attack:
            socketio.emit('attack_highlight', {'attack': None})
            emit('status_update', {'status': f'{current_attack} Attack Stopped'})
            current_attack = None
    else:
        emit('status_update', {'status': 'No active attack to stop'})

if __name__ == '__main__':
    init_db()
    socketio.run(app, host='0.0.0.0', port=5000)