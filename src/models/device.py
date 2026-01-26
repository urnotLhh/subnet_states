"""网络设备数据模型"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class DeviceMetrics:
    """设备指标数据类"""
    por: float = 0.0  # 端口占用率 (Port Occupancy Rate)
    par: float = 0.0  # 端口异常率 (Port Anomaly Rate)
    ier: float = 0.0  # 接口误码率 (Interface Error Rate)
    qdr: float = 0.0  # 队列丢包率 (Queue Discard Rate)
    # 历史数据，用于计算标准差权重
    history: List[dict] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "por": self.por,
            "par": self.par,
            "ier": self.ier,
            "qdr": self.qdr
        }
    
    def add_history(self, metrics: dict):
        """添加历史记录"""
        self.history.append(metrics.copy())


@dataclass
class NetworkDevice:
    """网络设备类"""
    ip: str
    is_snmp_enabled: bool = False
    metrics: DeviceMetrics = field(default_factory=DeviceMetrics)
    score: float = 0.0  # 计算后的单设备得分 (0-100)
    risk_level: str = "UNKNOWN"  # 风险等级: LOW, MEDIUM, HIGH, UNKNOWN
    
    def __post_init__(self):
        """初始化后处理"""
        if self.metrics is None:
            self.metrics = DeviceMetrics()
    
    def update_metrics(self, por: Optional[float] = None, 
                      par: Optional[float] = None,
                      ier: Optional[float] = None,
                      qdr: Optional[float] = None):
        """更新指标"""
        if por is not None:
            self.metrics.por = por
        if par is not None:
            self.metrics.par = par
        if ier is not None:
            self.metrics.ier = ier
        if qdr is not None:
            self.metrics.qdr = qdr
        
        # 保存历史记录
        self.metrics.add_history(self.metrics.to_dict())
    
    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "ip": self.ip,
            "is_snmp_enabled": self.is_snmp_enabled,
            "metrics": self.metrics.to_dict(),
            "score": self.score,
            "risk_level": self.risk_level
        }
