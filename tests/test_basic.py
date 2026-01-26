"""基础功能测试"""

import sys
from pathlib import Path

# 添加项目根目录到路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.models.device import NetworkDevice, DeviceMetrics
from src.core.calculator import MetricCalculator
from src.core.topology import TopologyAnalyzer


def test_device_metrics():
    """测试设备指标"""
    metrics = DeviceMetrics(por=0.5, par=0.01, ier=0.001, qdr=0.002)
    assert metrics.por == 0.5
    assert metrics.par == 0.01
    print("[OK] DeviceMetrics test passed")


def test_network_device():
    """测试网络设备"""
    device = NetworkDevice(ip="192.168.1.1", is_snmp_enabled=True)
    device.update_metrics(por=0.5, par=0.01)
    assert device.ip == "192.168.1.1"
    assert device.metrics.por == 0.5
    print("[OK] NetworkDevice test passed")


def test_normalize_metric():
    """测试指标归一化"""
    # 测试极低值（应该得高分）
    score1 = MetricCalculator.normalize_metric(0.000001)  # 非常小的值
    assert score1 > 70, f"极低值应该得高分，实际得分: {score1}"
    
    # 测试高值（应该得低分）
    score2 = MetricCalculator.normalize_metric(1000.0)
    assert score2 < 50, f"高值应该得低分，实际得分: {score2}"
    
    # 测试零值（应该得最高分）
    score3 = MetricCalculator.normalize_metric(0.0)
    assert score3 == 100.0, f"零值应该得最高分，实际得分: {score3}"
    
    print(f"[OK] Metric normalization test passed (very low: {score1:.2f}, high: {score2:.2f}, zero: {score3:.2f})")


def test_dynamic_weights():
    """测试动态权重计算"""
    history = [
        {"por": 0.5, "par": 0.01, "ier": 0.001, "qdr": 0.002},
        {"por": 0.6, "par": 0.02, "ier": 0.002, "qdr": 0.003},
        {"por": 0.4, "par": 0.01, "ier": 0.001, "qdr": 0.001},
    ]
    weights = MetricCalculator.calculate_dynamic_weights(history)
    
    assert len(weights) == 4
    assert abs(sum(weights.values()) - 1.0) < 0.01, "权重总和应该接近 1.0"
    print(f"[OK] Dynamic weights test passed: {weights}")


def test_device_score():
    """测试设备得分计算"""
    metrics = {"por": 0.5, "par": 0.01, "ier": 0.001, "qdr": 0.002}
    score = MetricCalculator.calculate_device_score(metrics)
    
    assert 0 <= score <= 100, f"得分应该在 0-100 范围内，实际: {score}"
    print(f"[OK] Device score calculation test passed: {score:.2f}")


def test_betweenness_centrality():
    """测试介数中心性计算"""
    edges = [
        ("192.168.1.1", "192.168.1.254"),
        ("192.168.1.254", "192.168.1.100"),
        ("192.168.1.1", "192.168.1.100"),
    ]
    centrality = TopologyAnalyzer.calculate_betweenness_centrality(edges)
    
    assert len(centrality) > 0
    print(f"[OK] Betweenness centrality test passed: {centrality}")


if __name__ == "__main__":
    print("Running basic functionality tests...\n")
    
    try:
        test_device_metrics()
        test_network_device()
        test_normalize_metric()
        test_dynamic_weights()
        test_device_score()
        test_betweenness_centrality()
        
        print("\n[SUCCESS] All tests passed!")
    except AssertionError as e:
        print(f"\n[FAIL] Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Test error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
