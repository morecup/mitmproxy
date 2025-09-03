#!/usr/bin/env python3
"""
Debug启动脚本for mitmweb
"""
import sys
import os

# 确保使用正确的Python路径
sys.path.insert(0, os.path.dirname(__file__))

# 导入mitmproxy主模块
from mitmproxy.tools.main import mitmweb

if __name__ == "__main__":
    # 设置调试参数
    sys.argv = [
        "mitmweb",
        "--listen-port", "8080",
        "--web-port", "8081",
        # 添加其他需要的参数
    ]
    
    # 启动mitmweb
    mitmweb()