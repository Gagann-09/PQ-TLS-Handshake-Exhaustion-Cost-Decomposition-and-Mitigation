#!/usr/bin/env python3
"""Test packet capture directly."""
import sys
import time
import subprocess
sys.path.insert(0, '.')

from src.instrumentation.packets import start_packet_capture, stop_packet_capture


def main():
    # Start the lab
    subprocess.run(
        ['docker', 'compose', '-f', 'lab/network/docker-compose-c4.yml', 'up', '-d'],
        check=True, capture_output=True
    )
    time.sleep(15)

    # Get container ID
    result = subprocess.run(
        ['docker', 'compose', '-f', 'lab/network/docker-compose-c4.yml', 'ps', '-q', 'tls-server'],
        capture_output=True, text=True
    )
    cid = result.stdout.strip()
    print('container:', cid)

    # Start capture
    session = start_packet_capture(cid, port=4433, interface='eth0')
    print('session started:', session.started, 'error:', session.error)
    time.sleep(2)

    # Run some workload
    docker_result = subprocess.run([
        'docker', 'exec', 'network-workload-client-1',
        'python', '-c', '''
import json, sys
sys.path.insert(0, "/src")
from src.workload.client import generate_attempts
groups = ["MLKEM768"]
sigalgs = ["mldsa65"]
for a in generate_attempts(host="tls-server", port=4433, mode="normal_completion", max_attempts=10, max_duration_seconds=10, groups=groups, sigalgs=sigalgs):
    print(json.dumps({"outcome": a.outcome, "error": a.error}))
'''
    ], capture_output=True, text=True, timeout=30)
    print('workload stdout:', docker_result.stdout[:200])

    time.sleep(1)

    # Stop capture
    capture = stop_packet_capture(session)
    print('capture success:', capture.success)
    print('capture meta:', capture.meta)
    print('capture error:', capture.error)

    # Cleanup
    subprocess.run(['docker', 'compose', '-f', 'lab/network/docker-compose-c4.yml', 'down'], check=True, capture_output=True)


if __name__ == '__main__':
    main()