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
    # 将脚本名替换为 mitmweb，保留所有传入的参数
    sys.argv[0] = "mitmweb"
    
    # 启动mitmweb，传递所有命令行参数
    mitmweb()