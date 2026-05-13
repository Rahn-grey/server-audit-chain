"""
日志采集层。

提供两种采集模式：
- 直接采集：监听系统命令日志文件，实时捕获命令执行记录
- 堡垒机接收：运行 HTTP 端点，接收堡垒机上传的日志批次

用法:
    # 直接采集模式
    python -m src.collector.agent --mode direct --log-file /var/log/commands.log

    # 堡垒机接收模式
    python -m src.collector.agent --mode bastion --listen-port 5001

    # 混合模式（同时支持）
    python -m src.collector.agent --mode both
"""
