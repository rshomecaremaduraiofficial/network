import random
import time
import datetime

class TrafficSimulator:
    def __init__(self):
        self.anomaly_threshold = 0.85
        self.protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'SSH']
        self.threat_types = ['Normal', 'DDoS Attack', 'SQL Injection', 'Port Scan', 'Brute Force']
        self.threat_severities = {
            'Normal': 'Safe',
            'DDoS Attack': 'Critical',
            'SQL Injection': 'High',
            'Port Scan': 'Medium',
            'Brute Force': 'High'
        }
        
        # Seed standard IPs
        self.internal_ips = [f"10.0.0.{i}" for i in range(10, 50)]
        self.external_ips = [
            "185.190.140.23", "203.0.113.5", "198.51.100.42", "45.33.32.156",
            "8.8.8.8", "1.1.1.1", "93.184.216.34", "104.244.42.1"
        ]
        self.malicious_ips = [
            "193.56.28.14", "45.143.203.54", "80.243.218.115", "109.236.85.90", "185.220.101.5"
        ]
        
        # History
        self.packets_history = []
        self.alerts_history = []
        self.total_packets_checked = 0
        self.total_threats_detected = 0
        
        # Cumulative threat breakdown counts matching UI starting metrics
        self.threat_counts = {
            'Normal': 0,
            'DDoS Attack': 0,
            'SQL Injection': 0,
            'Port Scan': 0,
            'Brute Force': 0
        }
        
        # Generate initial history
        self._generate_initial_data(50)
        
    def _generate_initial_data(self, count):
        now = datetime.datetime.now()
        for i in range(count):
            # Stagger timestamps backward
            p_time = now - datetime.timedelta(seconds=(count - i) * 2)
            packet = self._generate_single_packet(p_time)
            self.packets_history.append(packet)
            
            # If threat, maybe add to alert
            if packet['threat'] != 'Normal':
                alert = self._create_alert_from_packet(packet)
                self.alerts_history.append(alert)

    def _generate_single_packet(self, timestamp=None):
        if not timestamp:
            timestamp = datetime.datetime.now()
            
        threat_roll = random.random()
        # Dynamic Normal vs Anomaly threshold based on target network security
        if threat_roll < self.anomaly_threshold:
            threat = 'Normal'
            src_ip = random.choice(self.internal_ips + self.external_ips)
            dest_ip = random.choice(self.internal_ips)
            protocol = random.choice(self.protocols)
            length = random.randint(64, 1500)
            confidence = round(random.uniform(0.98, 0.999), 4)
            info = "Standard network exchange"
        else:
            threat = random.choice(self.threat_types[1:])
            src_ip = random.choice(self.malicious_ips)
            dest_ip = random.choice(self.internal_ips)
            
            if threat == 'DDoS Attack':
                protocol = random.choice(['TCP', 'UDP'])
                length = random.choice([64, 1200, 1500])
                confidence = round(random.uniform(0.92, 0.998), 4)
                info = f"High volume rate anomaly. Protocol: {protocol} Flooding detected."
            elif threat == 'SQL Injection':
                protocol = 'HTTP'
                length = random.randint(250, 600)
                confidence = round(random.uniform(0.88, 0.985), 4)
                info = "Suspicious SQL characters 'UNION SELECT' detected in request URL."
            elif threat == 'Port Scan':
                protocol = 'TCP'
                length = 64
                confidence = round(random.uniform(0.95, 0.999), 4)
                info = f"Sequential port connection attempts. Ports probed: {random.randint(20, 1000)}"
            else:  # Brute Force
                protocol = random.choice(['SSH', 'HTTP'])
                length = random.randint(80, 150)
                confidence = round(random.uniform(0.90, 0.991), 4)
                info = f"Repeated login failures detected from IP: {src_ip}"
                
        severity = self.threat_severities[threat]
        
        return {
            "id": f"PKT-{random.randint(100000, 999999)}",
            "time": timestamp.strftime("%H:%M:%S"),
            "timestamp": timestamp.timestamp(),
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "protocol": protocol,
            "length": length,
            "threat": threat,
            "confidence": confidence,
            "severity": severity,
            "info": info
        }

    def _create_alert_from_packet(self, packet):
        return {
            "id": f"ALT-{random.randint(1000, 9999)}",
            "time": packet['time'],
            "type": packet['threat'],
            "src_ip": packet['src_ip'],
            "dest_ip": packet['dest_ip'],
            "severity": packet['severity'],
            "status": "Active" if packet['severity'] in ['High', 'Critical'] else "Warning",
            "confidence": packet['confidence'],
            "info": packet['info']
        }

    def get_live_update(self):
        # Generate 1 to 4 new packets
        new_packets_count = random.randint(1, 4)
        new_packets = []
        now = datetime.datetime.now()
        
        for _ in range(new_packets_count):
            packet = self._generate_single_packet(now)
            self.packets_history.append(packet)
            
            # Increment overall statistics
            self.total_packets_checked += 1
            self.threat_counts[packet['threat']] = self.threat_counts.get(packet['threat'], 0) + 1
            if packet['threat'] != 'Normal':
                self.total_threats_detected += 1
                alert = self._create_alert_from_packet(packet)
                self.alerts_history.insert(0, alert)  # Add new alert to the start
                new_packets.append(packet)
            else:
                new_packets.append(packet)
                
        # Keep packet history size capped at 100
        if len(self.packets_history) > 100:
            self.packets_history = self.packets_history[-100:]
            
        # Keep alerts history size capped at 50
        if len(self.alerts_history) > 50:
            self.alerts_history = self.alerts_history[:50]
            
        return {
            "new_packets": new_packets,
            "total_packets": self.total_packets_checked,
            "total_threats": self.total_threats_detected,
            "current_severity": "CRITICAL" if len(self.alerts_history) > 0 and self.alerts_history[0]['severity'] == 'Critical' else "NORMAL"
        }

    def get_history(self):
        return self.packets_history

    def get_alerts(self):
        return self.alerts_history

    def get_aggregated_stats(self):
        # Calculate rates and protocol proportions
        protocol_counts = {}
        for pkt in self.packets_history:
            protocol_counts[pkt['protocol']] = protocol_counts.get(pkt['protocol'], 0) + 1
            
        return {
            "protocols": protocol_counts,
            "threats": self.threat_counts,
            "overall": {
                "packets_checked": self.total_packets_checked,
                "threats_detected": self.total_threats_detected,
                "detection_ratio": round((self.total_threats_detected / self.total_packets_checked) * 100, 2) if self.total_packets_checked > 0 else 0.0
            }
        }

    def get_model_performance(self):
        # Realistic machine learning metrics
        # Confusion matrix: Rows = Actual (Normal, DDoS, SQLi, PortScan, BruteForce)
        # Cols = Predicted (Normal, DDoS, SQLi, PortScan, BruteForce)
        confusion_matrix = [
            [992, 3, 1, 4, 0],   # Actual Normal
            [2, 485, 0, 10, 3],  # Actual DDoS
            [1, 0, 195, 2, 2],   # Actual SQL Injection
            [5, 8, 0, 282, 0],   # Actual Port Scan
            [0, 2, 4, 1, 143]    # Actual Brute Force
        ]
        
        # ROC coordinates for DDoS (Class 1), SQLi (Class 2), PortScan (Class 3)
        roc_data = {
            "DDoS": [
                {"fpr": 0.00, "tpr": 0.00},
                {"fpr": 0.01, "tpr": 0.85},
                {"fpr": 0.02, "tpr": 0.94},
                {"fpr": 0.05, "tpr": 0.98},
                {"fpr": 0.10, "tpr": 0.99},
                {"fpr": 0.20, "tpr": 0.995},
                {"fpr": 1.00, "tpr": 1.00}
            ],
            "SQL_Injection": [
                {"fpr": 0.00, "tpr": 0.00},
                {"fpr": 0.02, "tpr": 0.78},
                {"fpr": 0.04, "tpr": 0.88},
                {"fpr": 0.08, "tpr": 0.95},
                {"fpr": 0.15, "tpr": 0.97},
                {"fpr": 0.30, "tpr": 0.99},
                {"fpr": 1.00, "tpr": 1.00}
            ],
            "Port_Scan": [
                {"fpr": 0.00, "tpr": 0.00},
                {"fpr": 0.01, "tpr": 0.92},
                {"fpr": 0.03, "tpr": 0.96},
                {"fpr": 0.07, "tpr": 0.98},
                {"fpr": 0.12, "tpr": 0.99},
                {"fpr": 1.00, "tpr": 1.00}
            ]
        }
        
        # Epoch training progress (20 epochs)
        epochs = list(range(1, 21))
        train_loss = [0.65, 0.48, 0.35, 0.28, 0.22, 0.18, 0.15, 0.12, 0.10, 0.09, 0.08, 0.07, 0.06, 0.05, 0.05, 0.04, 0.04, 0.03, 0.03, 0.03]
        val_loss =   [0.68, 0.52, 0.38, 0.30, 0.25, 0.20, 0.17, 0.15, 0.13, 0.12, 0.11, 0.10, 0.09, 0.09, 0.08, 0.08, 0.08, 0.07, 0.07, 0.07]
        train_acc =  [0.72, 0.81, 0.86, 0.90, 0.92, 0.94, 0.95, 0.96, 0.97, 0.97, 0.98, 0.98, 0.98, 0.99, 0.99, 0.99, 0.99, 0.99, 0.99, 0.99]
        val_acc =    [0.70, 0.79, 0.84, 0.88, 0.90, 0.92, 0.93, 0.94, 0.95, 0.95, 0.96, 0.96, 0.97, 0.97, 0.97, 0.97, 0.98, 0.98, 0.98, 0.98]
        
        return {
            "accuracy": 0.9872,
            "precision": 0.9824,
            "recall": 0.9791,
            "f1_score": 0.9807,
            "confusion_matrix": confusion_matrix,
            "roc_data": roc_data,
            "epochs": epochs,
            "train_loss": train_loss,
            "val_loss": val_loss,
            "train_acc": train_acc,
            "val_acc": val_acc
        }
