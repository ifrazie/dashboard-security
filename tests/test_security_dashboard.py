import pytest
from datetime import datetime, timedelta
from security_dashboard import create_mock_threat_intel, create_mock_anomalies, load_data

def test_create_mock_threat_intel():
    num_records = 100
    df = create_mock_threat_intel(num_records)
    assert len(df) == num_records
    assert set(df.columns) == {'timestamp', 'ioc_type', 'value', 'severity', 'threat_actor', 'source'}
    assert all(df['severity'].isin(['Low', 'Medium', 'High', 'Critical']))

def test_create_mock_anomalies():
    days = 7
    points_per_day = 24
    df = create_mock_anomalies(days, points_per_day)
    assert len(df) == days * points_per_day * 3  # 3 metrics per time point
    assert set(df.columns) == {'timestamp', 'metric', 'value', 'is_anomaly'}
    assert all(df['metric'].isin(['login_failures', 'egress_traffic_mb', 'cpu_utilization_percent']))

def test_load_data():
    threat_intel_df, anomalies_df = load_data()
    assert not threat_intel_df.empty
    assert not anomalies_df.empty
    assert 'severity' in threat_intel_df.columns
    assert 'is_anomaly' in anomalies_df.columns
