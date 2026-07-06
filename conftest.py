"""
Root conftest.py — garantiza que el paquete 'app' sea importable
desde cualquier entorno: local, CI, Docker.
"""
import sys
import os

# Inserta la raíz del repositorio al inicio del sys.path
# para que 'from app.X import Y' funcione sin PYTHONPATH externo.
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
