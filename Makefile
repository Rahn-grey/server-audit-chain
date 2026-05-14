# 服务器操作审计系统 - 快捷命令

SHELL := /bin/bash
.PHONY: install test test-coverage run-api run-cli clean keys demo

# 安装依赖
install:
	pip install -r requirements.txt

# 运行所有测试
test:
	python -m pytest tests/ -v --tb=short

# 运行测试并生成覆盖率报告
test-coverage:
	python -m pytest tests/ -v --tb=short --cov=src --cov-report=term --cov-report=html:coverage_report

# 启动Flask API (demo模式, MockBCOS)
run-api:
	AUDIT_SYSTEM_MODE=demo FLASK_APP=src.api.routes \
	python -m flask run --host 0.0.0.0 --port 5000 --debug

# 运行CLI工具
run-cli:
	python -m src.cli.audit_cli $(filter-out $@,$(MAKECMDGOALS))

# 一键演示 (MockBCOS 端到端验证)
demo:
	AUDIT_SYSTEM_MODE=demo python scripts/e2e_demo.py --batches 3 --logs-per-batch 100 --verbose

# 清理
clean:
	rm -rf debug_data/*.json debug_data/*.db
	rm -rf __pycache__ src/**/__pycache__ tests/__pycache__ bcos/**/__pycache__
	rm -rf .pytest_cache coverage_report
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

# 生成Ed25519密钥对
keys:
	python scripts/generate_keys.py --output-dir ./keys
