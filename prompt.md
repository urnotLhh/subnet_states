基于您提供的设计文档（`README.md`）以及“只做策略判定、底层调用 `scout` 工具”的核心逻辑，我为您设计了一个 **分层架构（Layered Architecture）** 的 Python 项目结构。

这个架构的核心理念是 **关注点分离**：将“数据获取”（调用 scout）、“核心算法”（数学计算、图论）和“业务流程”（评估逻辑）完全分开，便于维护和测试。

### 1. 系统架构设计 (System Architecture)

我们将系统划分为四个主要层次：

1. **接口层 (Interface Layer)**: 处理命令行参数（CLI），解析用户输入的子网 CIDR。
2. **业务逻辑层 (Service/Logic Layer)**: 这是系统的“大脑”。负责编排评估流程（先做冗余评估，不通过再做综合评估），并最终判定速率等级。
3. **核心算法层 (Core/Algorithm Layer)**: 纯数学和逻辑计算。包含归一化、动态权重计算、介数中心性计算（图算法）。这部分不依赖外部 IO。
4. **适配器层 (Adapter/Infrastructure Layer)**: 负责与外部工具 `scout` 交互。它将 Python 的指令转换为 shell 命令，并将 `scout` 返回的文本/JSON 转换为 Python 对象。

---

### 2. 建议的项目目录结构

```text
subnet_states/
├── README.md                   # 您刚才写的文档
├── requirements.txt            # 依赖包 (如 networkx, numpy, click)
├── setup.py                    # 安装脚本
├── conf/
│   └── config.yaml             # 配置文件 (存放阈值 θ, 采样比例等)
├── src/
│   ├── __init__.py
│   ├── main.py                 # 【入口】程序入口，CLI 命令行定义
│   │
│   ├── models/                 # 【数据层】定义内部数据结构
│   │   ├── __init__.py
│   │   ├── device.py           # Device 类 (存储 POR, PAR, IER, QDR 等指标)
│   │   └── subnet.py           # Subnet 类 (包含设备列表、拓扑图)
│   │
│   ├── core/                   # 【核心算法层】纯计算逻辑
│   │   ├── __init__.py
│   │   ├── calculator.py       # 数学计算 (归一化、标准差权重、综合得分)
│   │   └── topology.py         # 图论算法 (构建图、计算介数中心性)
│   │
│   ├── services/               # 【业务逻辑层】流程控制
│   │   ├── __init__.py
│   │   └── assessor.py         # 评估器 (实现"冗余评估"和"综合评估"的流程跳转)
│   │
│   └── adapters/               # 【适配器层】与 scout 交互
│       ├── __init__.py
│       └── scout_client.py     # 封装 subprocess 调用 scout，解析结果
│
└── tests/                      # 单元测试
    ├── test_algorithms.py
    └── test_scout_parser.py

```

---

### 3. 各层级详细代码骨架

这里用 Python 代码展示每一层应该放什么内容，以及它们是如何交互的。

#### (1) `src/models/device.py` (数据模型)

用于标准化数据流转，避免在各层之间传递字典（Dict）。

```python
from dataclasses import dataclass, field
from typing import Dict

@dataclass
class DeviceMetrics:
    por: float = 0.0  # 端口占用率
    par: float = 0.0  # 端口异常率
    ier: float = 0.0  # 接口误码率
    qdr: float = 0.0  # 队列丢包率
    # 历史数据，用于计算标准差权重
    history: list = field(default_factory=list) 

@dataclass
class NetworkDevice:
    ip: str
    is_snmp_enabled: bool = False
    metrics: DeviceMetrics = field(default_factory=DeviceMetrics)
    score: float = 0.0  # 计算后的单设备得分
    risk_level: str = "UNKNOWN"

```

#### (2) `src/adapters/scout_client.py` (适配器层)

这是唯一允许调用 `subprocess` 的地方。它假装自己是 `scout`，对外屏蔽命令行细节。

```python
import subprocess
import json
from typing import List, Dict
from src.models.device import NetworkDevice

class ScoutClient:
    def __init__(self, scout_path="scout"):
        self.scout_path = scout_path

    def check_alive_and_snmp(self, subnet: str) -> List[NetworkDevice]:
        """
        调用 scout 探测子网内存活且支持 SNMP 的设备
        命令示例: scout discover --subnet 192.168.1.0/24 --output json
        """
        # 模拟调用外部命令
        # result = subprocess.run([self.scout_path, "discover", subnet], capture_output=True)
        # data = json.loads(result.stdout)
        
        # 伪代码返回
        return [NetworkDevice(ip="192.168.1.1", is_snmp_enabled=True)]

    def fetch_metrics(self, ip: str) -> Dict:
        """
        调用 scout 获取指定设备的 SNMP 指标 (POR, PAR, IER, QDR)
        """
        pass

    def fetch_topology(self, subnet: str):
        """
        调用 scout 获取路由表信息用于构建拓扑
        """
        pass

```

#### (3) `src/core/calculator.py` & `topology.py` (算法层)

实现文档中的数学公式。

```python
import numpy as np
import networkx as nx  # 推荐使用 networkx 处理图算法

class MetricCalculator:
    @staticmethod
    def normalize_metrics(value, max_power, most_freq_power):
        """
        实现文档中的：科学计数法分段函数归一化
        映射到 1-100 范围
        """
        # 实现具体的数学公式...
        return normalized_score

    @staticmethod
    def calculate_dynamic_weights(metric_history):
        """
        实现文档中的：基于标准差系数的动态权重计算
        """
        pass

class TopologyAnalyzer:
    @staticmethod
    def calculate_betweenness(edges, nodes):
        """
        实现文档中的：介数中心性计算
        Input: 路由表生成的边
        Output: 每个节点的 centrality score
        """
        G = nx.DiGraph()
        G.add_edges_from(edges)
        # networkx 自带介数中心性算法，可以直接用，也可以自己实现
        return nx.betweenness_centrality(G)

```

#### (4) `src/services/assessor.py` (业务逻辑层)

将上述组件串联起来，执行决策逻辑。

```python
from src.adapters.scout_client import ScoutClient
from src.core.calculator import MetricCalculator
from src.core.topology import TopologyAnalyzer

class SubnetAssessor:
    def __init__(self, scout: ScoutClient):
        self.scout = scout

    def assess(self, subnet_cidr: str) -> str:
        """
        主流程
        """
        # 1. 识别设备
        devices = self.scout.check_alive_and_snmp(subnet_cidr)
        
        # 2. 采集初步指标 (POR)
        for dev in devices:
            raw_data = self.scout.fetch_metrics(dev.ip)
            dev.metrics.por = raw_data.get('por')

        # --- 第一层：冗余容量评估 ---
        if self._check_redundancy_capacity(devices):
            return "LEVEL_HIGH_SPEED"  # 通过，直接返回高速

        # --- 第二层：综合状态评估 ---
        return self._comprehensive_assessment(subnet_cidr, devices)

    def _check_redundancy_capacity(self, devices):
        """
        逻辑：若所有设备 POR < 阈值，则通过
        """
        threshold = 0.5 # 假设阈值
        return all(d.metrics.por < threshold for d in devices)

    def _comprehensive_assessment(self, subnet, devices):
        """
        逻辑：单设备详细评分 + 拓扑权重计算
        """
        # 1. 获取更多指标 (PAR, IER, QDR)
        # 2. 计算单设备得分 (MetricCalculator)
        # 3. 获取路由表构建拓扑 (scout.fetch_topology)
        # 4. 计算介数中心性 (TopologyAnalyzer)
        # 5. 加权求和得到子网总分
        # 6. 根据总分返回 速率等级
        return "LEVEL_LOW_SPEED"

```

#### (5) `src/main.py` (入口)

```python
import sys
from src.services.assessor import SubnetAssessor
from src.adapters.scout_client import ScoutClient

def main():
    target_subnet = sys.argv[1] # 或使用 argparse/click 解析
    
    # 依赖注入
    client = ScoutClient(scout_path="/usr/bin/scout")
    assessor = SubnetAssessor(client)
    
    # 执行评估
    result_level = assessor.assess(target_subnet)
    
    print(f"Target: {target_subnet}")
    print(f"Recommended Scan Rate: {result_level}")

if __name__ == "__main__":
    main()

```

### 总结

* **scout_client.py** 负责脏活累活（执行命令、解析字符串）。
* **assessor.py** 负责照着您的文档流程图走（先看 A，不行再看 B）。
* **calculator.py** 负责照着您的文档公式算数。
* 这种结构非常适合您的需求：因为探测逻辑在外部工具里，Python 端主要是 **策略调度** 和 **数据处理**。