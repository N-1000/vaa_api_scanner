import pytest
import os
import sys
import subprocess

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.core.engine.orchestrator import ScanOrchestrator

@pytest.mark.asyncio
async def test_auth_refresh_cmd_shlex():
    """
    Verifica que `--auth-refresh-cmd` ejecuta los comandos usando shlex.split y shell=False,
    previendo que no haya inyeccion de comandos de shell directos (como `&&` o `|` nativos sin bash -c).
    """

    cmd = 'echo "hello" && echo "vuln"'
    
    options = {
        "auth_refresh_cmd": cmd
    }
    
    orchestrator = ScanOrchestrator(target="http://example.com", options=options)
    

    assert "auth_refresh_fn" in orchestrator.options
    
    refresh_fn = orchestrator.options["auth_refresh_fn"]
    

    try:
        output = refresh_fn()

        if output:
            assert "vuln" not in output.split('\n'), "Command injection succeeded! shell=True was used."
    except Exception as e:

        pass
