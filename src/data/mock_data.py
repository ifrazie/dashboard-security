# mock_data.py (Save this data generation logic if you want, or include it directly in the main app script)
import pandas as pd
import random
from datetime import datetime, timedelta

def create_mock_threat_intel(num_records=100):
    """Generates mock threat intelligence data."""
    data = []
    ioc_types = ['ip_address', 'domain', 'file_hash', 'url']
    severities = ['Low', 'Medium', 'High', 'Critical']
    threat_actors = ['APT_Shadow', 'CrimsonSpider', 'GenericBotnet', 'PhishingGroupX', None] # None represents unknown
    base_time = datetime.now()

    for i in range(num_records):
        ioc_type = random.choice(ioc_types)
        if ioc_type == 'ip_address':
            value = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        elif ioc_type == 'domain':
            value = f"malicious-domain-{random.randint(100, 999)}.com"
        elif ioc_type == 'file_hash':
            value = ''.join(random.choices('abcdef0123456789', k=64)) # SHA256 example
        else: # url
            value = f"http://{random.choice(['evil-site', 'phish-central', 'update-service'])}/payload{random.randint(1, 100)}.exe"

        data.append({
            'timestamp': base_time - timedelta(days=random.randint(0, 30), hours=random.randint(0,23)),
            'ioc_type': ioc_type,
            'value': value,
            'severity': random.choice(severities),
            'threat_actor': random.choice(threat_actors),
            'source': random.choice(['Internal Scan', 'OSINT Feed', 'Partner Intel'])
        })
    df = pd.DataFrame(data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df.sort_values(by='timestamp', ascending=False)

def create_mock_anomalies(days=7, points_per_day=24):
    """Generates mock time-series anomaly data."""
    data = []
    metrics = ['login_failures', 'egress_traffic_mb', 'cpu_utilization_percent']
    base_time = datetime.now() - timedelta(days=days)

    for metric in metrics:
        for i in range(days * points_per_day):
            ts = base_time + timedelta(hours=i // len(metrics), minutes=random.randint(0, 59)) # Approximate hourly data points
            is_anomaly = False
            if metric == 'login_failures':
                value = random.gauss(5, 2) # Normal distribution around 5
                if random.random() < 0.03: # 3% chance of anomaly
                    value = random.gauss(25, 5) # Anomaly distribution around 25
                    is_anomaly = True
            elif metric == 'egress_traffic_mb':
                value = random.gauss(100, 20)
                if random.random() < 0.02:
                    value = random.gauss(500, 50)
                    is_anomaly = True
            else: # cpu_utilization_percent
                value = random.gauss(30, 10)
                if random.random() < 0.04:
                     value = random.gauss(90, 5)
                     is_anomaly = True

            value = max(0, value) # Ensure non-negative values
            if metric == 'cpu_utilization_percent':
                 value = min(100, value) # Cap CPU at 100

            data.append({
                'timestamp': ts,
                'metric': metric,
                'value': round(value, 2),
                'is_anomaly': is_anomaly
            })

    df = pd.DataFrame(data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df.sort_values(by='timestamp')

# --- Generate the data ---
threat_intel_df = create_mock_threat_intel(150)
anomalies_df = create_mock_anomalies(7) # Data for the last 7 days