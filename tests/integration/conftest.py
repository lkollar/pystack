import os
import subprocess
import sys

import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "requires_task_for_pid: requires macOS task_for_pid capability",
    )


@pytest.fixture(scope="session")
def requires_task_for_pid():
    if sys.platform != "darwin":
        return

    allow_skip = os.getenv("PYSTACK_ALLOW_TASK_FOR_PID_SKIP")

    with subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ) as process:
        try:
            from pystack.engine import get_process_threads

            try:
                list(get_process_threads(process.pid, stop_process=True))
                return
            except Exception as exc:
                exc_text = str(exc)
                if (
                    "task_for_pid" not in exc_text
                    and "Operation not permitted" not in exc_text
                ):
                    raise
                message = (
                    "macOS task_for_pid denied; sign the test Python with "
                    "get-task-allow or try running as root, or set "
                    "PYSTACK_ALLOW_TASK_FOR_PID_SKIP=1. "
                    f"Error: {exc}"
                )
                if allow_skip:
                    pytest.skip(message)
                pytest.fail(message)
        finally:
            process.terminate()
            process.kill()
