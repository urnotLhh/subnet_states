# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

subnet_states is a network assessment tool that evaluates subnet health and determines safe scanning rates for active network reconnaissance. It performs lightweight pre-assessment before intensive scans to prevent network congestion, outputting Rate Levels 1-5.

## Development Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .

# Run tests
python tests/test_basic.py

# Run CLI
python -m src.main --target 192.168.1.0/24

# With options
python -m src.main --target 192.168.1.0/24 --verbose --output json

# After installation
subnet_states --target 192.168.1.0/24
```

## Architecture

**4-layer clean architecture:**

1. **Interface Layer** (`src/main.py`): CLI using Click framework
2. **Business Logic Layer** (`src/services/assessor.py`): Two-tier assessment workflow
3. **Core Algorithm Layer** (`src/core/`): Pure mathematical calculations (no external dependencies)
4. **Adapter Layer** (`src/adapters/scout_client.py`): External tool integration (scout wrapper)

**Key design principle:** Strategy/execution separation - subnet_states makes decisions, scout tool executes. Falls back to mock data when scout unavailable.

## Two-Tier Assessment Algorithm

**Tier 1 (Fast Path):** Checks if all devices have POR < threshold (default 0.5). If yes, returns level_5 immediately.

**Tier 2 (Detailed):** Collects all four metrics → normalizes → calculates dynamic weights based on coefficient of variation → computes device scores → builds topology from routing tables → calculates betweenness centrality → computes subnet score using formula: `S_subnet = Σ (1 - C_B(v)) × S_device(v)`

## Core Metrics (SNMP-collected)

| Metric | Meaning | Range |
|--------|---------|-------|
| POR | Port Occupancy Rate | 0.0-1.0 |
| PAR | Port Anomaly Rate | 0.0-1.0 |
| IER | Interface Error Rate | 0.0-1.0 |
| QDR | Queue Discard Rate | 0.0-1.0 |

All metrics follow "lower is better" - normalization inverts this so higher scores = better health.

## Rate Levels

| Level | Score Range | Description |
|-------|-------------|-------------|
| level_5 | ≥ 90 | Ultra-high speed |
| level_4 | ≥ 75 | High speed |
| level_3 | ≥ 60 | Medium speed |
| level_2 | ≥ 40 | Low speed |
| level_1 | < 40 | Ultra-low speed |

## Key Implementation Details

- **Metric normalization** uses scientific notation-based piecewise function to handle different scales
- **Dynamic weighting** based on coefficient of variation (CV = std_dev / mean), constrained to 0.1-0.4 range
- **Centrality weighting** formula `(1 - C_B(v))` means critical nodes get lower weight, making their failures more visible
- **Mock data mode** generates realistic data when scout unavailable, marked with `[MOCK]` in logs
- **Configuration** in `conf/config.yaml` controls all thresholds and parameters

## Exit Codes

- 0: Success (score ≥ 60)
- 1: Low score warning (score < 60)
- 130: User interrupt (Ctrl+C)

## Development Rules

- 运行环境为 Linux
- 在回复中描述关键问题和关键修改
- 不要粉饰太平，如果写了模拟数据，要特别标注出来并提示用户，避免造成误解和混淆
- 如果对命令有任何疑问，先提出疑问，确认方案之后再进行修改
- 对于长任务，建立 todo list，避免由于网络中断导致必须从头开始的问题
