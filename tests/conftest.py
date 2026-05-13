"""pytest fixtures。"""

import os
import sys

# 确保在debug模式下运行测试
os.environ["AUDIT_SYSTEM_MODE"] = "demo"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from src.crypto.key_manager import generate_key_pair, get_public_key_fingerprint
from src.debug.data_generator import generate_batch
from src.debug.mock_bcos import reset_shared_network


@pytest.fixture(autouse=True)
def _reset_consensus():
    """每个测试前重置共享共识网络，确保测试隔离。"""
    reset_shared_network()
    yield


@pytest.fixture
def mock_bcos():
    from src.debug.mock_bcos import MockBCOS
    bcos = MockBCOS()
    bcos.reset_ledger()
    return bcos


@pytest.fixture
def mock_es():
    from src.debug.mock_es import MockES
    es = MockES(db_path=":memory:")
    return es


@pytest.fixture
def key_pair():
    return generate_key_pair()


@pytest.fixture
def sample_logs():
    return generate_batch("batch_test_001", log_count=50)


@pytest.fixture
def multi_batch_logs():
    from src.debug.data_generator import generate_multi_batch
    return generate_multi_batch(num_batches=3, logs_per_batch=20)
