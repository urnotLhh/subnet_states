"""拓扑分析器 - 实现图论算法"""

import networkx as nx
from typing import List, Tuple, Dict, Optional


class TopologyAnalyzer:
    """拓扑分析器，实现介数中心性计算等图算法"""
    
    @staticmethod
    def calculate_betweenness_centrality(edges: List[Tuple[str, str]], 
                                         nodes: Optional[List[str]] = None,
                                         normalized: bool = True) -> Dict[str, float]:
        """
        计算介数中心性 (Betweenness Centrality)
        
        介数中心性衡量一个节点在所有最短路径中出现的频率
        值越高，说明该节点在网络中越关键
        
        Args:
            edges: 边列表，格式为 [(source_ip, target_ip), ...]
            nodes: 节点列表，如果为 None 则从 edges 中提取
            normalized: 是否归一化（除以可能的最大值）
        
        Returns:
            每个节点的介数中心性字典 {ip: centrality_value}
        """
        if not edges:
            return {}
        
        # 构建有向图
        G = nx.DiGraph()
        
        # 添加节点
        if nodes:
            G.add_nodes_from(nodes)
        else:
            # 从边中提取所有节点
            all_nodes = set()
            for source, target in edges:
                all_nodes.add(source)
                all_nodes.add(target)
            G.add_nodes_from(all_nodes)
        
        # 添加边
        G.add_edges_from(edges)
        
        # 如果图为空或只有一个节点，返回零值
        if len(G.nodes()) <= 1:
            return {node: 0.0 for node in G.nodes()}
        
        # 计算介数中心性
        # networkx 的 betweenness_centrality 默认是归一化的
        centrality = nx.betweenness_centrality(G, normalized=normalized)
        
        return centrality
    
    @staticmethod
    def build_topology_from_routes(routes: List[Dict]) -> Tuple[List[Tuple[str, str]], List[str]]:
        """
        从路由表信息构建拓扑
        
        Args:
            routes: 路由信息列表，每个元素包含 'dest', 'next_hop' 等信息
                   格式: [{'dest': '192.168.1.0/24', 'next_hop': '192.168.1.1'}, ...]
        
        Returns:
            (edges, nodes) 元组
            edges: 边列表 [(source, target), ...]
            nodes: 节点列表
        """
        edges = []
        nodes = set()
        
        for route in routes:
            source = route.get('source')  # 当前设备 IP
            next_hop = route.get('next_hop')  # 下一跳 IP
            dest = route.get('dest')  # 目标网段
            
            if source and next_hop:
                edges.append((source, next_hop))
                nodes.add(source)
                nodes.add(next_hop)
            
            # 如果目标网段是单个 IP，也可以作为节点
            if dest:
                # 提取 IP 地址（去除 CIDR 后缀）
                dest_ip = dest.split('/')[0]
                if source:
                    nodes.add(dest_ip)
        
        return list(edges), list(nodes)
    
    @staticmethod
    def find_key_nodes(centrality: Dict[str, float], 
                      threshold: float = 0.1) -> List[str]:
        """
        识别关键节点（Key Nodes）
        
        Args:
            centrality: 介数中心性字典
            threshold: 阈值，中心性高于此值的节点被认为是关键节点
        
        Returns:
            关键节点 IP 列表
        """
        if not centrality:
            return []
        
        max_centrality = max(centrality.values()) if centrality.values() else 0.0
        if max_centrality == 0:
            return []
        
        # 使用相对阈值
        relative_threshold = threshold * max_centrality
        
        key_nodes = [
            ip for ip, cent in centrality.items()
            if cent >= relative_threshold
        ]
        
        return key_nodes
