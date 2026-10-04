#!/usr/bin/env python3
"""Test CPU measurement directly."""
import sys
import time
import subprocess
sys.path.insert(0, '.')

from src.instrumentation.cpu import start_cpu_sampling, stop_cpu_sampling


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

    # Start CPU sampling
    session = start_cpu_sampling(cid, interval=1.0)
    print('session started:', session.started, 'pid:', session.pid, 'error:', session.error)

    # Run some workload
    docker_result = subprocess.run([
        'docker', 'exec', 'network-workload-client-1',
        'python', '-c',
        'import json, sys; sys.path.insert(0, "/src"); from src.workload.client import generate_attempts; groups = ["MLKEM768"]; sigalgs = ["mldsa65"]; [print(json.dumps({"outcome": a.outcome, "error": a.error})) for a in generate_attempts(host="tls-server", port=4433, mode="normal_completion", max_attempts=50, max_duration_seconds=10, groups=groups, sigalgs=sigalgs)]'
    ], capture_output=True, text=True, timeout=30)
    print('workload attempts:', len(docker_result.stdout.strip().splitlines()))

    time.sleep(2)

    # Stop CPU sampling
    cpu_result = stop_cpu_sampling(session)
    print('cpu_result:', cpu_result)
    if cpu_result:
        print('  cpu_seconds:', cpu_result.cpu_seconds)
        print('  pid:', cpu_result.pid)
        print('  samples:', len(cpu_result.samples.cpu_percent))

    # Cleanup
    subprocess.run(['docker', 'compose', '-f', 'lab/network/docker-compose-c4.yml', 'down'], check=True, capture_output=True)


if __name__ == '__main__':
    main()