"""子网数据模型"""

from dataclasses import dataclass, field
from typing import List, Optional
import networkx as nx

from .device import NetworkDevice


@dataclass
class Subnet:
    """子网类，包含设备列表和拓扑信息"""
    cidr: str
    devices: List[NetworkDevice] = field(default_factory=list)
    topology: Optional[nx.DiGraph] = None
    betweenness_centrality: dict = field(default_factory=dict)
    overall_score: float = 0.0  # 子网综合得分
    rate_level: str = "UNKNOWN"  # 速率等级
    
    def add_device(self, device: NetworkDevice):
        """添加设备"""
        self.devices.append(device)
    
    def get_device_by_ip(self, ip: str) -> Optional[NetworkDevice]:
        """根据 IP 获取设备"""
        for device in self.devices:
            if device.ip == ip:
                return device
        return None
    
    def build_topology(self, edges: List[tuple]):
        """构建拓扑图
        
        Args:
            edges: 边列表，格式为 [(source_ip, target_ip), ...]
        """
        self.topology = nx.DiGraph()
        # 添加所有设备节点
        for device in self.devices:
            self.topology.add_node(device.ip)
        # 添加边
        for source, target in edges:
            if source in [d.ip for d in self.devices] and target in [d.ip for d in self.devices]:
                self.topology.add_edge(source, target)
    
    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "cidr": self.cidr,
            "device_count": len(self.devices),
            "devices": [d.to_dict() for d in self.devices],
            "overall_score": self.overall_score,
            "rate_level": self.rate_level
        }
