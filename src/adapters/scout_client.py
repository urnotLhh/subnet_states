"""Scout 客户端 - 封装与 scout 工具的交互"""

import logging
from typing import List, Dict

from src.models.device import NetworkDevice
from src.adapters.scout import ScoutTool, DNMAP_AVAILABLE, PYSNMP_AVAILABLE

logger = logging.getLogger(__name__)


class ScoutClient:
    """Scout 工具客户端，使用内置 scout 模块进行网络探测"""

    def __init__(self, snmp_community: str = "public", snmp_port: int = 161,
                 timeout: int = 30, retry_count: int = 3):
        """
        初始化 Scout 客户端

        Args:
            snmp_community: SNMP 团体名
            snmp_port: SNMP 端口
            timeout: 操作超时时间（秒）
            retry_count: 失败重试次数

        Raises:
            RuntimeError: 依赖不完整时抛出异常
        """
        self.timeout = timeout
        self.retry_count = retry_count
        self.snmp_community = snmp_community
        self.snmp_port = snmp_port

        # 检查依赖是否可用
        missing = []
        if not DNMAP_AVAILABLE:
            missing.append("dnmap (需要 /home/lihaihong/dnmap/data_plane/run_core.sh)")
        if not PYSNMP_AVAILABLE:
            missing.append("pysnmp")

        if missing:
            raise RuntimeError(
                f"Scout 依赖不完整，缺少: {', '.join(missing)}。"
                f"请确保 dnmap 已编译且 run_core.sh 可执行，pysnmp 已安装 (pip install pysnmp)"
            )

        # 初始化内置 scout 工具
        self._scout = ScoutTool(snmp_community, snmp_port)
        logger.info("Scout 工具已就绪 (dnmap ICMP + PySNMP)")

    def check_alive_and_snmp(self, subnet: str) -> List[NetworkDevice]:
        """
        探测子网内存活且支持 SNMP 的设备

        Args:
            subnet: 子网 CIDR，如 "192.168.1.0/24"

        Returns:
            设备列表

        Raises:
            RuntimeError: 设备发现失败时抛出异常
        """
        result = self._scout.discover(subnet)

        if "error" in result:
            raise RuntimeError(f"设备发现失败: {result['error']}")

        devices = []
        for dev_data in result.get("devices", []):
            device = NetworkDevice(
                ip=dev_data.get("ip", ""),
                is_snmp_enabled=dev_data.get("snmp_enabled", False)
            )
            devices.append(device)

        logger.info(f"发现 {len(devices)} 台设备")
        return devices

    def fetch_metrics(self, ip: str) -> Dict:
        """
        获取指定设备的 SNMP 指标 (POR, PAR, IER, QDR)

        Args:
            ip: 设备 IP 地址

        Returns:
            指标字典 {'por': 0.5, 'par': 0.01, 'ier': 0.001, 'qdr': 0.002}

        Raises:
            RuntimeError: 指标采集失败时抛出异常
        """
        result = self._scout.get_metrics(ip)

        if "error" in result:
            raise RuntimeError(f"指标采集失败 ({ip}): {result['error']}")

        return {
            "por": float(result.get("por", 0.0)),
            "par": float(result.get("par", 0.0)),
            "ier": float(result.get("ier", 0.0)),
            "qdr": float(result.get("qdr", 0.0))
        }

    def fetch_topology(self, subnet: str) -> List[Dict]:
        """
        获取路由表信息用于构建拓扑

        Args:
            subnet: 子网 CIDR

        Returns:
            路由信息列表 [{"source": "192.168.1.1", "dest": "192.168.2.0/24", "next_hop": "192.168.1.254"}, ...]

        Raises:
            RuntimeError: 拓扑获取失败时抛出异常
        """
        result = self._scout.get_topology(subnet)

        if "error" in result:
            raise RuntimeError(f"拓扑获取失败: {result['error']}")

        return result.get("routes", [])
