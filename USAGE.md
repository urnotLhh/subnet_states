# 使用说明

## 安装依赖

### 系统依赖

Scout 模块使用 Nmap 进行设备发现，需要先安装 Nmap：

```bash
# Debian/Ubuntu
sudo apt install nmap

# CentOS/RHEL
sudo yum install nmap

# macOS
brew install nmap
```

### Python 依赖

```bash
pip install -r requirements.txt
```

或者使用 setup.py 安装：

```bash
pip install -e .
```

## 基本使用

### 命令行使用

```bash
# 基本用法 (需要 root 权限进行 UDP 扫描)
sudo python -m src.main --target 192.168.1.0/24

# 使用详细日志
sudo python -m src.main --target 192.168.1.0/24 --verbose

# 输出 JSON 格式
sudo python -m src.main --target 192.168.1.0/24 --output json

# 指定 SNMP 团体名 (默认 public)
sudo python -m src.main --target 192.168.1.0/24 --snmp-community private

# 指定配置文件
sudo python -m src.main --target 192.168.1.0/24 --config conf/config.yaml
```

### 安装后使用

如果使用 `pip install -e .` 安装后，可以直接使用：

```bash
sudo subnet_states --target 192.168.1.0/24
```

## 配置文件说明

配置文件位于 `conf/config.yaml`，主要配置项：

- **redundancy.por_threshold**: 第一层评估的端口占用率阈值（默认 0.5）
- **comprehensive.normalization**: 归一化参数
- **rate_levels**: 速率等级划分标准

## 输出说明

### 文本格式输出

```
============================================================
子网评估结果: 192.168.1.0/24
============================================================
综合评分: 85.23/100
速率等级: level_4 (高速)
设备数量: 3

设备详情:
------------------------------------------------------------

设备 IP: 192.168.1.1
  SNMP 支持: 是
  端口占用率 (POR): 45.00%
  端口异常率 (PAR): 2.00%
  接口误码率 (IER): 0.000500
  队列丢包率 (QDR): 0.001000
  设备得分: 82.50
  风险等级: LOW

[DECISION] 子网综合评分 85.23，建议使用 高速 扫描
============================================================
```

### JSON 格式输出

```json
{
  "subnet": "192.168.1.0/24",
  "overall_score": 85.23,
  "rate_level": "level_4",
  "rate_description": "高速",
  "device_count": 3,
  "devices": [...],
  "betweenness_centrality": {...},
  "message": "..."
}
```

## 速率等级说明

- **level_5 (极高速度)**: 得分 ≥ 90，网络状态极佳
- **level_4 (高速)**: 得分 ≥ 75，网络状态良好
- **level_3 (中速)**: 得分 ≥ 60，网络状态一般
- **level_2 (低速)**: 得分 ≥ 40，网络负载较高
- **level_1 (极低速)**: 得分 < 40，网络负载很高

## 模拟数据模式

如果系统中没有安装 Nmap 或 pysnmp 依赖不完整，程序会自动使用模拟数据进行测试。这在开发和测试阶段很有用。

模拟数据会：
- 生成 3 台模拟设备（IP 以 .1, .254, .100 结尾）
- 为不同设备生成不同的负载指标
- 生成简单的星型拓扑结构

**注意**：使用模拟数据时日志会显示 `[MOCK]` 标记，请注意区分真实数据和模拟数据。

## Scout 模块详解

Scout 是内置的网络探测模块，负责实际的数据采集工作。

### 架构设计

采用 **Nmap + PySNMP** 混合架构：
- **Nmap**: 负责广度发现，快速扫描子网内开启 SNMP 的设备
- **PySNMP**: 负责深度采集，获取设备的详细指标

### 功能列表

| 功能 | 方法 | 说明 |
|------|------|------|
| 设备发现 | `discover(subnet)` | 使用 Nmap UDP 扫描发现 SNMP 设备 |
| 指标采集 | `get_metrics(ip)` | 双采样法计算 POR/PAR/IER/QDR |
| 拓扑构建 | `get_topology(subnet)` | 读取路由表构建网络拓扑 |

### 指标采集原理

SNMP MIB 中的值是累计计数器 (Counter)，Scout 使用双采样法计算速率：

1. 读取 T1 时刻的计数器值
2. 等待采样间隔 (默认 1 秒)
3. 读取 T2 时刻的计数器值
4. 计算速率: `Rate = (T2 - T1) / Interval`

### SNMP OID 说明

| OID | 名称 | 用途 |
|-----|------|------|
| 1.3.6.1.2.1.4.3.0 | ipInReceives | 计算输入包速率 |
| 1.3.6.1.2.1.4.10.0 | ipOutRequests | 计算输出包速率 |
| 1.3.6.1.2.1.4.8.0 | ipInDiscards | 计算丢弃率 (QDR) |
| 1.3.6.1.2.1.4.4.0 | ipInHdrErrors | 计算错误率 (IER) |
| 1.3.6.1.2.1.4.5.0 | ipInAddrErrors | 计算错误率 (IER) |
| 1.3.6.1.2.1.4.21.1.7 | ipRouteNextHop | 构建拓扑 |
| 1.3.6.1.2.1.4.21.1.1 | ipRouteDest | 构建拓扑 |

### 权限要求

- **UDP 扫描需要 root 权限**: Nmap 的 UDP 扫描 (`-sU`) 需要原始套接字权限
- 建议使用 `sudo` 运行程序

### SNMP 配置

- 默认团体名: `public`
- 默认端口: `161`
- 可通过命令行参数 `--snmp-community` 修改团体名

## 测试

运行基础功能测试：

```bash
python tests/test_basic.py
```

## 注意事项

1. **Nmap 安装**: 本工具依赖 Nmap 进行设备发现，请确保系统已安装 Nmap。

2. **Root 权限**: UDP 扫描需要 root 权限，建议使用 `sudo` 运行。

3. **SNMP 支持**: 只有支持 SNMP 的设备才能进行完整的状态评估。不支持 SNMP 的设备无法采集指标。

4. **SNMP 团体名**: 默认使用 `public`，如果目标设备使用其他团体名（如 `private`），需要通过 `--snmp-community` 参数指定。

5. **网络权限**: 执行网络探测需要相应的网络权限。

6. **配置文件**: 如果配置文件不存在或格式错误，程序会使用默认配置继续运行。

7. **模拟数据警告**: 如果看到 `[MOCK]` 标记，说明正在使用模拟数据，结果仅供参考。

8. **防火墙**: 确保运行脚本的机器允许发送 UDP 包并接收回包。
