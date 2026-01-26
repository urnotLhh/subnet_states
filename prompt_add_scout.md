这是实现 `scout` 工具的完整架构设计方案和核心代码实现。

基于你的需求，我们采用 **"Nmap 负责广度发现，PySNMP 负责深度采集"** 的混合架构。

---

### 1. 系统架构设计

该工具包含三个核心模块：

1. **Discovery Module (发现模块)**:
* **职责**: 快速扫描子网，找出开启 UDP 161 (SNMP) 的存活主机。
* **核心库**: `python-nmap` (调用 Nmap 二进制文件)。
* **原因**: Python 原生 socket 扫描 UDP 速度慢且不可靠，Nmap 是事实标准。


2. **Metrics Module (指标模块)**:
* **职责**: 对特定 IP 进行“采样-等待-采样”，计算瞬时速率 (Rate)。
* **核心库**: `pysnmp`。
* **逻辑**: 


3. **Topology Module (拓扑模块)**:
* **职责**: 读取设备的路由表 (`ipRouteTable`)，构建网络连接关系。
* **核心库**: `pysnmp`。



---

### 2. 环境准备

你需要安装以下 Python 库，并确保系统已安装 Nmap 软件。

```bash
# 安装 Python 依赖
pip install python-nmap pysnmp

```

> **注意**: Windows 用户必须先下载并安装 [Nmap for Windows](https://nmap.org/download.html)，并确保将其添加到系统环境变量 PATH 中。

---

### 3. 核心代码实现 (`scout.py`)

将以下代码保存为 `scout.py`。这是一个完整的、可运行的 CLI 工具雏形。

```python
import sys
import time
import json
import argparse
import nmap
from pysnmp.hlapi import *

# ================= 配置区域 =================
SNMP_COMMUNITY = 'public'  # 默认 SNMP 团体名
SNMP_PORT = 161
SAMPLE_INTERVAL = 1.0      # 计算速率时的采样间隔(秒)
# ===========================================

class SnmpClient:
    """SNMP 操作封装类"""
    def __init__(self, community, port=161):
        self.community = community
        self.port = port

    def get(self, ip, oids):
        """获取单个或多个 OID 的值"""
        handler = getCmd(
            SnmpEngine(),
            CommunityData(self.community),
            UdpTransportTarget((ip, self.port), timeout=1.0, retries=1),
            ContextData(),
            *[ObjectType(ObjectIdentity(oid)) for oid in oids]
        )
        
        errorIndication, errorStatus, errorIndex, varBinds = next(handler)
        
        if errorIndication or errorStatus:
            return None
        
        # 返回结果字典 {oid: value}
        return {str(varBind[0]): varBind[1] for varBind in varBinds}

    def walk(self, ip, root_oid):
        """遍历 (Walk) 一个 OID 树/表"""
        results = []
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
        return results

class ScoutTool:
    def __init__(self):
        self.snmp = SnmpClient(SNMP_COMMUNITY, SNMP_PORT)

    def discover(self, subnet):
        """功能 1: 发现子网内 SNMP 设备"""
        nm = nmap.PortScanner()
        # -sU: UDP扫描, -p 161: SNMP端口, --open: 只显示开放的
        try:
            nm.scan(hosts=subnet, arguments='-sU -p 161 --open')
        except nmap.PortScannerError:
            return {"error": "Nmap scan failed. Is Nmap installed?"}

        devices = []
        for host in nm.all_hosts():
            # 确认 161 端口是 open 状态
            if nm[host].has_udp(161) and nm[host]['udp'][161]['state'] == 'open':
                devices.append({
                    "ip": host,
                    "snmp_enabled": True,
                    "status": "up"
                })
        
        return {"devices": devices}

    def get_metrics(self, target_ip):
        """功能 2: 计算 SNMP 指标 (POR, PAR, IER, QDR)"""
        # 定义 OID 映射 (MIB-II)
        # ifInUcastPkts: 1.3.6.1.2.1.2.2.1.11.{index} (这里简化取 index=1 或总和，实际需遍历接口)
        # 为了演示，我们假设设备只有一个主要接口，或者我们获取 System 级别的统计 (IP-MIB)
        
        # 使用 IP-MIB 的全局计数器 (比接口级更通用)
        oids = {
            "ipInReceives": "1.3.6.1.2.1.4.3.0",    # 输入包总数
            "ipOutRequests": "1.3.6.1.2.1.4.10.0",  # 输出包总数
            "ipInDiscards": "1.3.6.1.2.1.4.8.0",    # 输入丢弃 (QDR相关)
            "ipInHdrErrors": "1.3.6.1.2.1.4.4.0",   # 输入头部错误
            "ipInAddrErrors": "1.3.6.1.2.1.4.5.0"   # 输入地址错误
        }
        
        oid_list = list(oids.values())

        # 1. 第一次采样 (T1)
        data_t1 = self.snmp.get(target_ip, oid_list)
        if not data_t1:
            return {"error": "SNMP Unreachable"}

        # 2. 等待 Delta T
        time.sleep(SAMPLE_INTERVAL)

        # 3. 第二次采样 (T2)
        data_t2 = self.snmp.get(target_ip, oid_list)
        if not data_t2:
            return {"error": "SNMP dropped during sampling"}

        # 4. 计算速率 (Rate) = (T2 - T1) / Interval
        metrics = {}
        
        # 辅助函数：提取数值
        def val(data, oid_key):
            return int(data.get(oids[oid_key], 0))

        # PAR: Packet Arrival Rate (包/秒)
        delta_in = val(data_t2, "ipInReceives") - val(data_t1, "ipInReceives")
        metrics['par'] = round(delta_in / SAMPLE_INTERVAL, 2)

        # POR: Packet Output Rate (包/秒)
        delta_out = val(data_t2, "ipOutRequests") - val(data_t1, "ipOutRequests")
        metrics['por'] = round(delta_out / SAMPLE_INTERVAL, 2)

        # IER: Input Error Rate (错误包/秒) - 也可以定义为 错误数/总包数 的比率
        delta_err = (val(data_t2, "ipInHdrErrors") + val(data_t2, "ipInAddrErrors")) - \
                    (val(data_t1, "ipInHdrErrors") + val(data_t1, "ipInAddrErrors"))
        metrics['ier'] = round(delta_err / SAMPLE_INTERVAL, 4)

        # QDR: Queue Drop Rate (丢包/秒)
        delta_drop = val(data_t2, "ipInDiscards") - val(data_t1, "ipInDiscards")
        metrics['qdr'] = round(delta_drop / SAMPLE_INTERVAL, 4)

        return metrics

    def get_topology(self, subnet):
        """功能 3: 构建拓扑 (基于路由表)"""
        # 1. 先发现设备
        discovery_res = self.discover(subnet)
        if "error" in discovery_res:
            return discovery_res
        
        routes = []
        
        # 2. 对每个设备拉取路由表
        for device in discovery_res['devices']:
            ip = device['ip']
            # OID: ipRouteNextHop (1.3.6.1.2.1.4.21.1.7)
            # OID: ipRouteDest (1.3.6.1.2.1.4.21.1.1)
            
            # 遍历路由表 NextHop 列
            next_hops = self.snmp.walk(ip, "1.3.6.1.2.1.4.21.1.7")
            dests = self.snmp.walk(ip, "1.3.6.1.2.1.4.21.1.1")
            
            # 简单的匹配逻辑 (实际情况需要根据索引严格匹配)
            # 假设 walk 返回的顺序是一致的
            for i in range(len(next_hops)):
                nh_oid, nh_val = next_hops[i]
                dest_oid, dest_val = dests[i]
                
                # 过滤掉本地回环和默认网关0.0.0.0 (可视情况保留)
                if nh_val != '0.0.0.0' and nh_val != '127.0.0.1':
                    routes.append({
                        "source": ip,
                        "dest": dest_val,
                        "next_hop": nh_val
                    })

        return {"routes": routes}

# ================= CLI 入口 =================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scout Network Tool")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: discover
    p_disc = subparsers.add_parser("discover", help="Discover SNMP devices")
    p_disc.add_argument("--subnet", required=True, help="CIDR subnet (e.g., 192.168.1.0/24)")
    p_disc.add_argument("--output", default="json", help="Output format")

    # Command: snmp (metrics)
    p_snmp = subparsers.add_parser("snmp", help="Get device metrics")
    p_snmp.add_argument("--target", required=True, help="Target IP address")
    p_snmp.add_argument("--output", default="json", help="Output format")

    # Command: topology
    p_topo = subparsers.add_parser("topology", help="Build topology from routes")
    p_topo.add_argument("--subnet", required=True, help="CIDR subnet to scan and build topo")
    p_topo.add_argument("--output", default="json", help="Output format")

    args = parser.parse_args()
    tool = ScoutTool()
    result = {}

    if args.command == "discover":
        result = tool.discover(args.subnet)
    elif args.command == "snmp":
        result = tool.get_metrics(args.target)
    elif args.command == "topology":
        result = tool.get_topology(args.subnet)
    else:
        parser.print_help()
        sys.exit(1)

    print(json.dumps(result, indent=2))

```

---

### 4. 代码逻辑详解

#### A. Discover (发现)

* **实现**: `tool.discover(args.subnet)`
* **逻辑**: 直接调用 `python-nmap`。
* **关键点**: 参数 `-sU -p 161 --open` 是核心。这会告诉 Nmap 发送 UDP 包探测 SNMP 端口，并且只返回开启的设备。这是目前 Python 环境下最高效的实现方式。

#### B. SNMP Metrics (指标计算)

* **实现**: `tool.get_metrics(args.target)`
* **逻辑**:
1. 你需要的 POR/PAR/IER 都是**速率 (Rate)** 概念。
2. SNMP 数据库 (MIB) 里的值是 **Counter (累计计数器)**，它只会一直增加，不会自动清零。
3. **核心算法**:
* 读取 T1 时刻的值。
* `time.sleep(1.0)` (暂停1秒)。
* 读取 T2 时刻的值。
* `(T2 - T1) / 时间` = 每秒速率。




* **OID 选择**: 代码中使用了 `IP-MIB` 的全局计数器（如 `ipInReceives`），这对路由器/交换机来说是统计整机流量最简单的办法，无需遍历每一个物理接口。

#### C. Topology (拓扑)

* **实现**: `tool.get_topology(args.subnet)`
* **逻辑**:
1. 复用 `discover` 先找到所有 IP。
2. 对每个 IP 执行 SNMP Walk，遍历 `ipRouteTable` (OID: `1.3.6.1.2.1.4.21`)。
3. 提取 `ipRouteNextHop` (下一跳) 和 `ipRouteDest` (目标网段)。
4. 通过分析 "我是谁 (Source)" 和 "我的下一跳是谁 (Next Hop)"，即可在前端（或其他逻辑中）画出拓扑连线。



### 5. 如何运行

**1. 发现设备:**

```powershell
python scout.py discover --subnet 192.168.1.0/24

```

**2. 获取指标 (POR/PAR...):**

```powershell
python scout.py snmp --target 192.168.1.100

```

**3. 生成拓扑:**

```powershell
python scout.py topology --subnet 192.168.1.0/24

```

### 6. 需要注意的“坑”

1. **SNMP Community**: 代码默认写了 `public`。如果你的测试环境用了其他字符串（如 `private` 或 `admin`），请修改代码顶部的 `SNMP_COMMUNITY` 变量。
2. **Windows 防火墙**: 确保运行脚本的机器允许 Nmap 发送 UDP 包，且接收回包。
3. **PySNMP 版本**: PySNMP 库历史悠久，建议安装最新版或 `pysnmp-lextudio` 版本以获得最佳兼容性。

这个架构既满足了 `scout` 的功能需求，又避免了重写底层扫描协议的麻烦，是性价比最高的实现方案。
