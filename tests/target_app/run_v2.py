
"""
VAA Cyber-range v4.0.0 - Standalone Runner
Run this script directly from the target_app directory
"""

import sys
import os


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


from main_v2 import app
import uvicorn

if __name__ == "__main__":
    print(" Starting VAA Cyber-range v4.0.0...")
    print(" Server: http://127.0.0.1:8000")
    print(" API Docs: http://127.0.0.1:8000/docs")
    print(" Login: POST /api/v1/auth/token (username=admin, password=supersecret)")
    print("\n  WARNING: This is an intentionally vulnerable application for training!")
    print("   DO NOT expose to the internet!\n")
    
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
