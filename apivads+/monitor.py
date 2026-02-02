import os
import sys
from datetime import datetime
import subprocess

TODAY = datetime.now().strftime("%Y%m%d")
TRACE_PIPE = '/sys/kernel/debug/tracing/trace_pipe'
LOG_FILE = "./logs/out.txt"

def log_trace_data():
    if not os.path.exists("./logs"):
        os.mkdir("logs")

    with open(LOG_FILE, 'a') as log_file, open(TRACE_PIPE, 'r') as trace_pipe:

        print("Monitoring trace_pipe...")

        while True:
            line = trace_pipe.readline()
            if line:
                current_time = datetime.now().strftime("%H:%M:%S.") + str(datetime.now().microsecond)
                log_file.write(f"{current_time} {line}\n")
                log_file.flush()


def mount_debugfs():
    try:
        subprocess.run(['sudo', 'mount', '-t', 'debugfs', 'none', '/sys/kernel/debug'], check=True)
        print("debugfs successfully mounted at /sys/kernel/debug")
    except subprocess.CalledProcessError as e:
        print(f"Failed to mount debugfs: {e}")

def debugfs_is_mounted():
    with open('/proc/mounts', 'r') as f:
        mounts = f.readlines()
    
    for mount in mounts:
        if '/sys/kernel/debug' in mount and 'debugfs' in mount:
            return True
    return False

if __name__ == "__main__":
    if not debugfs_is_mounted():
        mount_debugfs()

    if os.path.exists(TRACE_PIPE):
        log_trace_data()
    else:
        print(f"Error: {TRACE_PIPE} does not exist.")
        exit(1)
