"""子网评估器 - 实现分层评估流程"""

import logging
import yaml
from pathlib import Path
from typing import Dict, Optional

from src.adapters.scout_client import ScoutClient
from src.core.calculator import MetricCalculator
from src.core.topology import TopologyAnalyzer
from src.models.device import NetworkDevice
from src.models.subnet import Subnet

logger = logging.getLogger(__name__)


class SubnetAssessor:
    """子网评估器，实现分层评估逻辑"""
    
    def __init__(self, scout: ScoutClient, config_path: Optional[str] = None):
        """
        初始化评估器
        
        Args:
            scout: Scout 客户端实例
            config_path: 配置文件路径，如果为 None 则使用默认路径
        """
        self.scout = scout
        self.config = self._load_config(config_path)
    
    def _load_config(self, config_path: Optional[str] = None) -> Dict:
        """加载配置文件"""
        if config_path is None:
            # 默认配置文件路径
            config_path = Path(__file__).parent.parent.parent / "conf" / "config.yaml"
        else:
            config_path = Path(config_path)
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            logger.info(f"配置文件加载成功: {config_path}")
            return config
        except FileNotFoundError:
            logger.warning(f"配置文件不存在: {config_path}，使用默认配置")
            return self._get_default_config()
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}，使用默认配置")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """获取默认配置"""
        return {
            "redundancy": {"por_threshold": 0.5},
            "comprehensive": {
                "normalization": {"max_power": 10, "most_freq_power": 5},
                "weight": {"use_std_coefficient": True, "min_weight": 0.1, "max_weight": 0.4},
                "topology": {"use_betweenness": True, "normalize_centrality": True}
            },
            "rate_levels": {
                "level_5": {"min_score": 90, "description": "极高速度"},
                "level_4": {"min_score": 75, "description": "高速"},
                "level_3": {"min_score": 60, "description": "中速"},
                "level_2": {"min_score": 40, "description": "低速"},
                "level_1": {"min_score": 0, "description": "极低速"}
            }
        }
    
    def assess(self, subnet_cidr: str) -> Dict:
        """
        主评估流程
        
        Args:
            subnet_cidr: 子网 CIDR，如 "192.168.1.0/24"
        
        Returns:
            评估结果字典，包含 score, rate_level, devices 等信息
        """
        logger.info(f"开始评估子网: {subnet_cidr}")
        
        # 1. 识别设备
        logger.info("正在调用 scout 探测设备...")
        devices = self.scout.check_alive_and_snmp(subnet_cidr)
        
        if not devices:
            logger.warning("未发现任何设备")
            return {
                "subnet": subnet_cidr,
                "overall_score": 0.0,
                "rate_level": "level_1",
                "device_count": 0,
                "devices": [],
                "message": "未发现任何设备"
            }
        
        logger.info(f"发现 {len(devices)} 台设备")
        
        # 2. 采集初步指标 (POR)
        logger.info("正在采集初步指标 (POR)...")
        for device in devices:
            if device.is_snmp_enabled:
                raw_data = self.scout.fetch_metrics(device.ip)
                device.update_metrics(por=raw_data.get('por', 0.0))
                logger.debug(f"设备 {device.ip} POR: {device.metrics.por:.2%}")
        
        # 3. 第一层：冗余容量评估
        logger.info("执行第一层评估：冗余容量评估...")
        if self._check_redundancy_capacity(devices):
            logger.info("✓ 冗余容量充足，直接返回高速等级")
            return {
                "subnet": subnet_cidr,
                "overall_score": 100.0,
                "rate_level": "level_5",
                "device_count": len(devices),
                "devices": [d.to_dict() for d in devices],
                "message": "冗余容量充足，建议使用极高速度扫描"
            }
        
        # 4. 第二层：综合状态评估
        logger.info("执行第二层评估：综合状态评估...")
        return self._comprehensive_assessment(subnet_cidr, devices)
    
    def _check_redundancy_capacity(self, devices: list) -> bool:
        """
        第一层：冗余容量评估
        逻辑：若所有设备 POR < 阈值，则通过
        
        Args:
            devices: 设备列表
        
        Returns:
            是否通过冗余容量评估
        """
        threshold = self.config.get("redundancy", {}).get("por_threshold", 0.5)
        
        # 只检查支持 SNMP 的设备
        snmp_devices = [d for d in devices if d.is_snmp_enabled]
        if not snmp_devices:
            logger.warning("没有支持 SNMP 的设备，无法进行冗余容量评估")
            return False
        
        all_below_threshold = all(d.metrics.por < threshold for d in snmp_devices)
        
        if all_below_threshold:
            logger.info(f"所有设备 POR < {threshold:.2%}，通过冗余容量评估")
        else:
            high_por_devices = [d for d in snmp_devices if d.metrics.por >= threshold]
            logger.info(f"发现 {len(high_por_devices)} 台设备 POR >= {threshold:.2%}，需要综合评估")
        
        return all_below_threshold
    
    def _comprehensive_assessment(self, subnet_cidr: str, devices: list) -> Dict:
        """
        第二层：综合状态评估
        逻辑：单设备详细评分 + 拓扑权重计算
        
        Args:
            subnet_cidr: 子网 CIDR
            devices: 设备列表
        
        Returns:
            评估结果字典
        """
        # 1. 获取完整指标 (PAR, IER, QDR)
        logger.info("正在采集完整指标 (PAR, IER, QDR)...")
        for device in devices:
            if device.is_snmp_enabled:
                raw_data = self.scout.fetch_metrics(device.ip)
                device.update_metrics(
                    par=raw_data.get('par', 0.0),
                    ier=raw_data.get('ier', 0.0),
                    qdr=raw_data.get('qdr', 0.0)
                )
                logger.debug(
                    f"设备 {device.ip} - POR: {device.metrics.por:.2%}, "
                    f"PAR: {device.metrics.par:.2%}, IER: {device.metrics.ier:.4f}, "
                    f"QDR: {device.metrics.qdr:.4f}"
                )
        
        # 2. 计算动态权重
        norm_config = self.config.get("comprehensive", {}).get("normalization", {})
        max_power = norm_config.get("max_power", 10)
        most_freq_power = norm_config.get("most_freq_power", 5)
        
        # 收集所有设备的历史数据
        all_history = []
        for device in devices:
            if device.is_snmp_enabled and device.metrics.history:
                all_history.extend(device.metrics.history)
        
        # 计算权重
        weights = MetricCalculator.calculate_dynamic_weights(all_history)
        logger.debug(f"动态权重: {weights}")
        
        # 3. 计算单设备得分
        device_scores = {}
        for device in devices:
            if device.is_snmp_enabled:
                score = MetricCalculator.calculate_device_score(
                    device.metrics.to_dict(),
                    weights,
                    max_power,
                    most_freq_power
                )
                device.score = score
                device_scores[device.ip] = score
                
                # 确定风险等级
                if score >= 80:
                    device.risk_level = "LOW"
                elif score >= 60:
                    device.risk_level = "MEDIUM"
                else:
                    device.risk_level = "HIGH"
                
                logger.info(f"设备 {device.ip} 得分: {score:.2f} ({device.risk_level})")
        
        # 4. 获取路由表构建拓扑
        logger.info("正在调用 scout 获取拓扑信息...")
        routes = self.scout.fetch_topology(subnet_cidr)
        
        # 5. 计算介数中心性
        betweenness_centrality = {}
        if routes and self.config.get("comprehensive", {}).get("topology", {}).get("use_betweenness", True):
            edges, nodes = TopologyAnalyzer.build_topology_from_routes(routes)
            if edges:
                betweenness_centrality = TopologyAnalyzer.calculate_betweenness_centrality(
                    edges, nodes, normalized=True
                )
                logger.info(f"计算得到 {len(betweenness_centrality)} 个节点的介数中心性")
                
                # 识别关键节点
                key_nodes = TopologyAnalyzer.find_key_nodes(betweenness_centrality, threshold=0.1)
                if key_nodes:
                    logger.info(f"发现 {len(key_nodes)} 个关键节点: {key_nodes}")
        
        # 6. 计算子网综合得分
        subnet_score = MetricCalculator.calculate_subnet_score(
            devices,
            betweenness_centrality,
            device_scores
        )
        
        logger.info(f"子网综合评分: {subnet_score:.2f}")
        
        # 7. 确定速率等级
        rate_level = self._determine_rate_level(subnet_score)
        rate_desc = self.config.get("rate_levels", {}).get(rate_level, {}).get("description", "未知")
        
        logger.info(f"建议速率等级: {rate_level} ({rate_desc})")
        
        # 构建结果
        result = {
            "subnet": subnet_cidr,
            "overall_score": subnet_score,
            "rate_level": rate_level,
            "rate_description": rate_desc,
            "device_count": len(devices),
            "devices": [d.to_dict() for d in devices],
            "betweenness_centrality": betweenness_centrality,
            "message": f"子网综合评分 {subnet_score:.2f}，建议使用 {rate_desc} 扫描"
        }
        
        return result
    
    def _determine_rate_level(self, score: float) -> str:
        """
        根据得分确定速率等级
        
        Args:
            score: 子网综合得分 (0-100)
        
        Returns:
            速率等级字符串 (level_1 到 level_5)
        """
        rate_levels = self.config.get("rate_levels", {})
        
        # 按分数从高到低检查
        for level_name in ["level_5", "level_4", "level_3", "level_2", "level_1"]:
            level_config = rate_levels.get(level_name, {})
            min_score = level_config.get("min_score", 0)
            if score >= min_score:
                return level_name
        
        return "level_1"  # 默认最低等级
