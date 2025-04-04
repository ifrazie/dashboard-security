def test_threat_intel_filtering(mock_threat_intel):
    filtered = mock_threat_intel[mock_threat_intel['severity'] == 'Critical']
    assert all(filtered['severity'] == 'Critical')

def test_anomaly_detection(mock_anomalies):
    anomalies = mock_anomalies[mock_anomalies['is_anomaly']]
    assert not anomalies.empty
    assert all(anomalies['value'] > 0)
