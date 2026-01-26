"""主入口 - CLI 命令行接口"""

import sys
import logging
import click
from pathlib import Path

from src.services.assessor import SubnetAssessor
from src.adapters.scout_client import ScoutClient


# 配置日志
def setup_logging(level: str = "INFO"):
    """设置日志"""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="[%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )


@click.command()
@click.option("--target", "-t", required=True, help="目标子网 CIDR，如 192.168.1.0/24")
@click.option("--config", "-c", help="配置文件路径（默认: conf/config.yaml）")
@click.option("--verbose", "-v", is_flag=True, help="显示详细日志")
@click.option("--output", "-o", type=click.Choice(["text", "json"]), default="text", help="输出格式")
def main(target, config, verbose, output):
    """
    子网状态评估工具
    
    对指定子网进行状态评估，输出建议的扫描速率等级。
    """
    # 设置日志级别
    log_level = "DEBUG" if verbose else "INFO"
    setup_logging(log_level)
    
    logger = logging.getLogger(__name__)
    
    try:
        # 初始化 Scout 客户端
        logger.info("初始化 Scout 客户端")
        scout_client = ScoutClient()
        
        # 初始化评估器
        assessor = SubnetAssessor(scout=scout_client, config_path=config)
        
        # 执行评估
        result = assessor.assess(target)
        
        # 输出结果
        if output == "json":
            import json
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            # 文本格式输出
            print("\n" + "="*60)
            print(f"子网评估结果: {result['subnet']}")
            print("="*60)
            print(f"综合评分: {result['overall_score']:.2f}/100")
            print(f"速率等级: {result['rate_level']} ({result.get('rate_description', '')})")
            print(f"设备数量: {result['device_count']}")
            print("\n设备详情:")
            print("-"*60)
            
            for device in result['devices']:
                print(f"\n设备 IP: {device['ip']}")
                print(f"  SNMP 支持: {'是' if device['is_snmp_enabled'] else '否'}")
                if device['is_snmp_enabled']:
                    metrics = device['metrics']
                    print(f"  端口占用率 (POR): {metrics['por']:.2%}")
                    print(f"  端口异常率 (PAR): {metrics['par']:.2%}")
                    print(f"  接口误码率 (IER): {metrics['ier']:.6f}")
                    print(f"  队列丢包率 (QDR): {metrics['qdr']:.6f}")
                    print(f"  设备得分: {device['score']:.2f}")
                    print(f"  风险等级: {device['risk_level']}")
            
            if result.get('betweenness_centrality'):
                print("\n关键节点 (介数中心性):")
                print("-"*60)
                sorted_nodes = sorted(
                    result['betweenness_centrality'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )
                for ip, centrality in sorted_nodes[:5]:  # 只显示前5个
                    print(f"  {ip}: {centrality:.4f}")
            
            print("\n" + "="*60)
            print(f"[DECISION] {result.get('message', '')}")
            print("="*60 + "\n")
        
        # 返回适当的退出码
        if result['overall_score'] >= 60:
            sys.exit(0)  # 成功
        else:
            sys.exit(1)  # 低分警告
    
    except KeyboardInterrupt:
        logger.info("\n用户中断操作")
        sys.exit(130)
    except Exception as e:
        logger.error(f"评估过程中发生错误: {e}", exc_info=verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()
