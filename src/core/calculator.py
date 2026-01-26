"""指标计算器 - 实现归一化和动态权重计算"""

import numpy as np
from typing import List, Dict, Tuple


class MetricCalculator:
    """指标计算器，实现文档中的数学公式"""
    
    @staticmethod
    def normalize_metric(value: float, max_power: int = 10, 
                         most_freq_power: int = 5) -> float:
        """
        基于科学计数法的分段函数归一化
        将不同量级的指标映射到 1-100 范围
        注意：所有指标都是值越小越好，所以值越小得分越高
        
        Args:
            value: 原始指标值（越小越好）
            max_power: 最大科学计数法幂次
            most_freq_power: 最常见幂次
        
        Returns:
            归一化后的得分 (1-100)，值越小得分越高
        """
        if value <= 0:
            return 100.0  # 无错误/无占用，得分最高
        
        # 计算科学计数法表示（幂次）
        if value >= 1:
            power = int(np.floor(np.log10(value)))
        else:
            power = int(np.floor(np.log10(value)))
        
        # 分段函数归一化
        # 策略：值越小（幂次越小），得分越高
        if power < -3:
            # 极小的值（如 0.0001 以下），得分 95-100
            normalized = 100 + power * 1.5  # power 为负，所以是加分
            normalized = max(95.0, min(100.0, normalized))
        elif power < 0:
            # 很小的值（如 0.001-0.1），得分 85-95
            normalized = 95 + power * 5
            normalized = max(85.0, min(95.0, normalized))
        elif power == 0:
            # 值在 0-1 之间（如占用率），线性映射到 60-85
            normalized = 85 - value * 25
            normalized = max(60.0, min(85.0, normalized))
        elif power <= most_freq_power:
            # 中等值（1-10^most_freq_power），得分 20-60
            normalized = 60 - (power - 1) * 8
            normalized = max(20.0, min(60.0, normalized))
        elif power <= max_power:
            # 大值（10^most_freq_power - 10^max_power），得分 1-20
            normalized = 20 * np.exp(-(power - most_freq_power) * 0.5)
            normalized = max(1.0, min(20.0, normalized))
        else:
            # 超出范围：最低分
            normalized = 1.0
        
        # 确保在 1-100 范围内
        return max(1.0, min(100.0, normalized))
    
    @staticmethod
    def calculate_dynamic_weights(metric_history: List[Dict[str, float]], 
                                  metric_names: List[str] = None) -> Dict[str, float]:
        """
        基于标准差系数的动态权重计算
        数据波动大的指标权重更高
        
        Args:
            metric_history: 历史指标数据列表，每个元素是一个包含各指标值的字典
            metric_names: 指标名称列表，如 ['por', 'par', 'ier', 'qdr']
        
        Returns:
            各指标的权重字典
        """
        if metric_names is None:
            metric_names = ['por', 'par', 'ier', 'qdr']
        
        if not metric_history or len(metric_history) < 2:
            # 历史数据不足，返回均匀权重
            return {name: 1.0 / len(metric_names) for name in metric_names}
        
        # 计算每个指标的标准差系数（变异系数）
        std_coefficients = {}
        for name in metric_names:
            values = [h.get(name, 0.0) for h in metric_history if name in h]
            if not values:
                std_coefficients[name] = 0.0
                continue
            
            mean_val = np.mean(values)
            if mean_val == 0:
                std_coefficients[name] = 0.0
            else:
                std_val = np.std(values)
                std_coefficients[name] = std_val / mean_val if mean_val > 0 else 0.0
        
        # 根据标准差系数分配权重
        total_coefficient = sum(std_coefficients.values())
        if total_coefficient == 0:
            # 所有指标都没有波动，返回均匀权重
            return {name: 1.0 / len(metric_names) for name in metric_names}
        
        # 归一化权重
        weights = {name: coeff / total_coefficient for name, coeff in std_coefficients.items()}
        
        # 确保权重在合理范围内（可选：限制最小/最大权重）
        min_weight = 0.1
        max_weight = 0.4
        for name in weights:
            weights[name] = max(min_weight, min(max_weight, weights[name]))
        
        # 重新归一化
        total = sum(weights.values())
        weights = {name: w / total for name, w in weights.items()}
        
        return weights
    
    @staticmethod
    def calculate_device_score(metrics: Dict[str, float], 
                               weights: Dict[str, float] = None,
                               max_power: int = 10,
                               most_freq_power: int = 5) -> float:
        """
        计算单设备综合得分
        
        Args:
            metrics: 设备指标字典 {'por': 0.5, 'par': 0.01, ...}
            weights: 各指标权重，如果为 None 则使用均匀权重
            max_power: 归一化参数
            most_freq_power: 归一化参数
        
        Returns:
            设备得分 (0-100)
        """
        if weights is None:
            # 默认均匀权重
            metric_names = ['por', 'par', 'ier', 'qdr']
            weights = {name: 1.0 / len(metric_names) for name in metric_names}
        
        # 归一化各指标
        normalized_scores = {}
        for metric_name, value in metrics.items():
            if metric_name in weights:
                normalized_scores[metric_name] = MetricCalculator.normalize_metric(
                    value, max_power, most_freq_power
                )
        
        # 加权求和
        total_score = sum(
            normalized_scores.get(name, 0) * weights.get(name, 0)
            for name in weights.keys()
        )
        
        return total_score
    
    @staticmethod
    def calculate_subnet_score(devices: List, 
                               betweenness_centrality: Dict[str, float],
                               device_scores: Dict[str, float]) -> float:
        """
        计算子网综合得分，结合拓扑权重
        
        公式: S_subnet = Σ (1 - C_B(v)) × S_device(v)
        关键设备的性能下降会对子网整体得分产生更严重的负面影响
        
        Args:
            devices: 设备列表
            betweenness_centrality: 介数中心性字典 {ip: centrality_value}
            device_scores: 设备得分字典 {ip: score}
        
        Returns:
            子网综合得分 (0-100)
        """
        if not devices:
            return 0.0
        
        # 归一化介数中心性值（如果需要）
        if betweenness_centrality:
            max_centrality = max(betweenness_centrality.values()) if betweenness_centrality.values() else 1.0
            if max_centrality > 0:
                normalized_centrality = {
                    ip: val / max_centrality 
                    for ip, val in betweenness_centrality.items()
                }
            else:
                normalized_centrality = {ip: 0.0 for ip in betweenness_centrality.keys()}
        else:
            normalized_centrality = {}
        
        # 计算加权得分
        total_score = 0.0
        for device in devices:
            ip = device.ip
            device_score = device_scores.get(ip, device.score)
            centrality = normalized_centrality.get(ip, 0.0)
            
            # 关键设备（高中心性）的权重降低，使得其性能下降影响更大
            weight = 1.0 - centrality
            total_score += weight * device_score
        
        # 平均得分
        return total_score / len(devices) if devices else 0.0
