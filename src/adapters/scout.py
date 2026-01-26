"""Scout 工具 - 使用 dnmap 发现设备，PySNMP 采集指标"""

import time
import logging
import subprocess
import shutil
import json
import os
from typing import List, Dict, Optional

# dnmap 路径配置
DNMAP_PATH = "/home/lihaihong/dnmap/data_plane/run_core.sh"
DNMAP_AVAILABLE = os.path.isfile(DNMAP_PATH) and os.access(DNMAP_PATH, os.X_OK)

try:
    from pysnmp.hlapi import (
        SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity, getCmd, nextCmd
    )
    PYSNMP_AVAILABLE = True
except ImportError:
    PYSNMP_AVAILABLE = False

logger = logging.getLogger(__name__)

# ================= 配置 =================
DEFAULT_SNMP_COMMUNITY = 'public'
DEFAULT_SNMP_PORT = 161
DEFAULT_SAMPLE_INTERVAL = 1.0  # 计算速率时的采样间隔(秒)
SUDO_PASSWORD = '14qiguaidemeng'  # sudo 密码（注意：硬编码密码有安全风险）
# ========================================


class SnmpClient:
    """SNMP 操作封装类"""

    def __init__(self, community: str = DEFAULT_SNMP_COMMUNITY, port: int = DEFAULT_SNMP_PORT):
        self.community = community
        self.port = port

    def get(self, ip: str, oids: List[str]) -> Optional[Dict[str, any]]:
        """获取单个或多个 OID 的值"""
        if not PYSNMP_AVAILABLE:
            logger.warning("pysnmp 未安装，无法执行 SNMP GET")
            return None

        try:
            handler = getCmd(
                SnmpEngine(),
                CommunityData(self.community),
                UdpTransportTarget((ip, self.port), timeout=2.0, retries=1),
                ContextData(),
                *[ObjectType(ObjectIdentity(oid)) for oid in oids]
            )

            errorIndication, errorStatus, errorIndex, varBinds = next(handler)

            if errorIndication:
                logger.debug(f"SNMP GET 错误 ({ip}): {errorIndication}")
                return None
            if errorStatus:
                logger.debug(f"SNMP GET 状态错误 ({ip}): {errorStatus.prettyPrint()}")
                return None

            # 返回结果字典 {oid: value}
            return {str(varBind[0]): varBind[1] for varBind in varBinds}
        except Exception as e:
            logger.debug(f"SNMP GET 异常 ({ip}): {e}")
            return None

    def walk(self, ip: str, root_oid: str) -> List[tuple]:
        """遍历 (Walk) 一个 OID 树/表"""
        if not PYSNMP_AVAILABLE:
            logger.warning("pysnmp 未安装，无法执行 SNMP WALK")
            return []

        results = []
        try:
            for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(self.community),
                UdpTransportTarget((ip, self.port), timeout=2.0, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity(root_oid)),
                lexicographicMode=False
            ):
                if errorIndication or errorStatus:
                    break
                for varBind in varBinds:
                    results.append((str(varBind[0]), str(varBind[1])))
        except Exception as e:
            logger.debug(f"SNMP WALK 异常 ({ip}): {e}")

        return results


class ScoutTool:
    """Scout 网络探测工具

    功能:
    1. discover: 发现子网内 SNMP 设备 (使用 dnmap ICMP Ping)
    2. get_metrics: 获取设备 SNMP 指标 (POR, PAR, IER, QDR)
    3. get_topology: 构建网络拓扑 (基于路由表)
    """

    def __init__(self, snmp_community: str = DEFAULT_SNMP_COMMUNITY,
                 snmp_port: int = DEFAULT_SNMP_PORT,
                 sample_interval: float = DEFAULT_SAMPLE_INTERVAL):
        self.snmp = SnmpClient(snmp_community, snmp_port)
        self.sample_interval = sample_interval

        # 检查依赖可用性
        if not DNMAP_AVAILABLE:
            logger.warning(f"dnmap 未找到或不可执行: {DNMAP_PATH}，discover 功能将不可用")
        if not PYSNMP_AVAILABLE:
            logger.warning("pysnmp 未安装，SNMP 采集功能将不可用")

    @property
    def is_available(self) -> bool:
        """检查 scout 工具是否可用（依赖是否安装）"""
        return DNMAP_AVAILABLE and PYSNMP_AVAILABLE

    def _verify_snmp(self, ip: str) -> bool:
        """通过 SNMP 请求验证设备是否支持 SNMP"""
        if not PYSNMP_AVAILABLE:
            return False
        # 尝试获取 sysDescr OID
        result = self.snmp.get(ip, ["1.3.6.1.2.1.1.1.0"])
        return result is not None

    def _run_dnmap(self, args: List[str], timeout: int = 300) -> tuple:
        """
        执行 dnmap 命令

        Args:
            args: dnmap 参数列表（不含 sudo 和 dnmap 路径）
            timeout: 超时时间（秒）

        Returns:
            (success: bool, result: str 或 error: str)
        """
        cmd = ['sudo', '-S', DNMAP_PATH] + args
        dnmap_dir = os.path.dirname(DNMAP_PATH)

        try:
            result = subprocess.run(
                cmd,
                input=SUDO_PASSWORD + '\n',
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=dnmap_dir
            )

            if result.returncode != 0:
                error_msg = result.stderr.strip() if result.stderr else f"dnmap 返回码: {result.returncode}"
                return False, error_msg

            return True, result.stdout

        except subprocess.TimeoutExpired:
            return False, f"dnmap 扫描超时（超过{timeout}秒）"
        except FileNotFoundError:
            return False, f"dnmap 未找到: {DNMAP_PATH}"
        except Exception as e:
            return False, f"扫描过程中发生错误: {e}"

    def discover(self, subnet: str) -> Dict:
        """
        发现子网内 SNMP 设备

        优化流程:
        1. ICMP Ping 扫描发现存活主机
        2. UDP 161 端口扫描筛选可能支持 SNMP 的主机
        3. 只对 161 端口开放的主机进行 SNMP 验证

        Args:
            subnet: CIDR 格式子网，如 "192.168.1.0/24"

        Returns:
            {"devices": [{"ip": "...", "snmp_enabled": True, "status": "up"}, ...]}
            或 {"error": "错误信息"}
        """
        if not DNMAP_AVAILABLE:
            return {"error": f"dnmap 未找到或不可执行: {DNMAP_PATH}"}

        # ========== 第一步: ICMP Ping 扫描发现存活主机 ==========
        logger.info(f"[1/2] ICMP Ping 扫描子网: {subnet}")

        success, result = self._run_dnmap(['-sP', '-t', subnet, '-oJ'])
        if not success:
            return {"error": f"ICMP 扫描失败: {result}"}

        alive_hosts = self._parse_dnmap_output(result)
        logger.info(f"发现 {len(alive_hosts)} 台存活主机")

        if not alive_hosts:
            return {"devices": []}

        # ========== 第二步: UDP 161 端口扫描 ==========
        logger.info(f"[2/2] UDP 161 端口扫描 ({len(alive_hosts)} 台主机)")

        # 将存活主机列表转为逗号分隔的字符串
        hosts_str = ','.join(alive_hosts)

        success, result = self._run_dnmap(['-sU', '-p', '161', '-t', hosts_str, '-oJ'])
        if not success:
            # UDP 扫描失败时，回退到对所有存活主机进行 SNMP 验证
            logger.warning(f"UDP 扫描失败: {result}，回退到逐个 SNMP 验证")
            snmp_devices = []
            for host in alive_hosts:
                if self._verify_snmp(host):
                    snmp_devices.append(host)
            snmp_hosts = snmp_devices
        else:
            snmp_hosts = self._parse_dnmap_output(result)

        logger.info(f"发现 {len(snmp_hosts)} 台 SNMP 设备 (UDP 161 端口开放)")

        # UDP 161 端口开放即认为支持 SNMP，无需再次验证
        devices = [{"ip": host, "snmp_enabled": True, "status": "up"} for host in snmp_hosts]
        return {"devices": devices}

    def _parse_dnmap_output(self, output: str) -> List[str]:
        """解析 dnmap JSON 输出，返回存活主机 IP 列表"""
        hosts = set()
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                # dnmap JSON 格式: {"ip":"192.168.1.1","port":0,"status":"open","type":"icmp"}
                if data.get('status') == 'open' and data.get('ip'):
                    hosts.add(data['ip'])
            except json.JSONDecodeError:
                # 跳过非 JSON 行（可能是状态信息）
                logger.debug(f"跳过非 JSON 行: {line}")
                continue
        return list(hosts)

    def get_metrics(self, target_ip: str) -> Dict:
        """
        获取设备 SNMP 指标 (POR, PAR, IER, QDR)

        使用双采样法计算速率:
        1. 读取 T1 时刻的计数器值
        2. 等待 sample_interval 秒
        3. 读取 T2 时刻的计数器值
        4. 计算速率 = (T2 - T1) / interval

        Args:
            target_ip: 目标设备 IP

        Returns:
            {"por": float, "par": float, "ier": float, "qdr": float}
            或 {"error": "错误信息"}
        """
        if not PYSNMP_AVAILABLE:
            return {"error": "pysnmp 未安装，请运行: pip install pysnmp"}

        # IP-MIB OID 定义
        oids = {
            "ipInReceives": "1.3.6.1.2.1.4.3.0",    # 输入包总数
            "ipOutRequests": "1.3.6.1.2.1.4.10.0",  # 输出包总数
            "ipInDiscards": "1.3.6.1.2.1.4.8.0",    # 输入丢弃 (QDR相关)
            "ipInHdrErrors": "1.3.6.1.2.1.4.4.0",   # 输入头部错误
            "ipInAddrErrors": "1.3.6.1.2.1.4.5.0"   # 输入地址错误
        }

        oid_list = list(oids.values())

        # 第一次采样 (T1)
        logger.debug(f"开始采样 T1 ({target_ip})")
        data_t1 = self.snmp.get(target_ip, oid_list)
        if not data_t1:
            return {"error": f"SNMP 不可达: {target_ip}"}

        # 等待采样间隔
        time.sleep(self.sample_interval)

        # 第二次采样 (T2)
        logger.debug(f"开始采样 T2 ({target_ip})")
        data_t2 = self.snmp.get(target_ip, oid_list)
        if not data_t2:
            return {"error": f"SNMP 采样中断: {target_ip}"}

        # 辅助函数：提取数值
        def val(data: Dict, oid_key: str) -> int:
            try:
                return int(data.get(oids[oid_key], 0))
            except (ValueError, TypeError):
                return 0

        # 计算速率
        interval = self.sample_interval

        # POR: Port Occupancy Rate - 这里用输出包速率近似
        delta_out = val(data_t2, "ipOutRequests") - val(data_t1, "ipOutRequests")
        por_rate = delta_out / interval if interval > 0 else 0

        # PAR: Port Anomaly Rate - 这里用输入包速率近似
        delta_in = val(data_t2, "ipInReceives") - val(data_t1, "ipInReceives")
        par_rate = delta_in / interval if interval > 0 else 0

        # IER: Interface Error Rate
        delta_err = (val(data_t2, "ipInHdrErrors") + val(data_t2, "ipInAddrErrors")) - \
                    (val(data_t1, "ipInHdrErrors") + val(data_t1, "ipInAddrErrors"))
        ier_rate = delta_err / interval if interval > 0 else 0

        # QDR: Queue Discard Rate
        delta_drop = val(data_t2, "ipInDiscards") - val(data_t1, "ipInDiscards")
        qdr_rate = delta_drop / interval if interval > 0 else 0

        # 将速率转换为比率 (0-1 范围)
        # 注意: 这里需要根据实际网络情况调整归一化参数
        # 假设最大速率为 10000 包/秒
        MAX_RATE = 10000.0

        metrics = {
            "por": min(1.0, por_rate / MAX_RATE),
            "par": min(1.0, par_rate / MAX_RATE),
            "ier": min(1.0, ier_rate / max(1, delta_in)) if delta_in > 0 else 0.0,  # 错误率 = 错误数/总包数
            "qdr": min(1.0, qdr_rate / max(1, delta_in)) if delta_in > 0 else 0.0   # 丢弃率 = 丢弃数/总包数
        }

        logger.debug(f"指标采集完成 ({target_ip}): {metrics}")
        return metrics

    def get_topology(self, subnet: str) -> Dict:
        """
        构建网络拓扑 (基于路由表)

        Args:
            subnet: CIDR 格式子网

        Returns:
            {"routes": [{"source": "...", "dest": "...", "next_hop": "..."}, ...]}
            或 {"error": "错误信息"}
        """
        # 先发现设备
        discovery_res = self.discover(subnet)
        if "error" in discovery_res:
            return discovery_res

        routes = []

        # 对每个设备拉取路由表
        for device in discovery_res.get('devices', []):
            ip = device['ip']
            logger.debug(f"获取路由表: {ip}")

            # OID: ipRouteNextHop (1.3.6.1.2.1.4.21.1.7)
            # OID: ipRouteDest (1.3.6.1.2.1.4.21.1.1)
            next_hops = self.snmp.walk(ip, "1.3.6.1.2.1.4.21.1.7")
            dests = self.snmp.walk(ip, "1.3.6.1.2.1.4.21.1.1")

            # 匹配路由条目
            for i in range(min(len(next_hops), len(dests))):
                nh_oid, nh_val = next_hops[i]
                dest_oid, dest_val = dests[i]

                # 过滤掉本地回环和无效条目
                if nh_val not in ('0.0.0.0', '127.0.0.1', ''):
                    routes.append({
                        "source": ip,
                        "dest": dest_val,
                        "next_hop": nh_val
                    })

        logger.info(f"获取到 {len(routes)} 条路由信息")
        return {"routes": routes}


# 全局单例
_scout_instance: Optional[ScoutTool] = None


def get_scout_tool(snmp_community: str = DEFAULT_SNMP_COMMUNITY,
                   snmp_port: int = DEFAULT_SNMP_PORT) -> ScoutTool:
    """获取 ScoutTool 单例"""
    global _scout_instance
    if _scout_instance is None:
        _scout_instance = ScoutTool(snmp_community, snmp_port)
    return _scout_instance
