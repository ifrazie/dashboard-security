import pytest
import sys
from pathlib import Path

# Add the project root directory to the Python path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from security_dashboard import create_mock_threat_intel, create_mock_anomalies  # noqa: E402

@pytest.fixture
def mock_threat_intel():
    return create_mock_threat_intel(50)

@pytest.fixture
def mock_anomalies():
    return create_mock_anomalies(3, 12)
