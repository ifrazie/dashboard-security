# This module will contain the correlation logic.
import pandas as pd
from datetime import datetime, timedelta

def correlate_findings(threat_intel_df, anomalies_df):
    """Correlates anomalies with recent critical IOCs."""
    # Filter for recent critical IOCs (last 7 days)
    recent_critical_iocs = threat_intel_df[
        (threat_intel_df['severity'] == 'Critical') &
        (threat_intel_df['timestamp'] >= datetime.now() - timedelta(days=7))
    ]

    # Extract unique IOC values (e.g., IPs, domains) from recent critical IOCs
    ioc_values = set(recent_critical_iocs['value'])

    # Add a correlation column to anomalies_df
    anomalies_df['correlated_with_ioc'] = anomalies_df['metric'].apply(
        lambda metric: any(ioc in metric for ioc in ioc_values)
    )

    return anomalies_df