"""
Cloud log sync engine for the TAR Honeypot (Docker edition).

Runs as a small standalone loop next to the dashboard. Every 15 seconds it
connects to the DigitalOcean host over SSH and pulls the Cowrie honeypot log
into the local hacker_data.json, which app.py then serves to the web pages.

The sync is incremental: only the bytes that were appended since the last
check are downloaded, so a log that grows to hundreds of megabytes is never
re-transferred in full.
"""

import paramiko
import time
import os

# ==========================================
# DigitalOcean server details (Docker environment)
# ==========================================
VM_IP = '167.172.85.182'
VM_PORT = 22022           # SSH port exposed by the host
VM_USER = 'root'
VM_PASS = 'w_Qm32_fbWQDyPc'

# Path of the Cowrie log inside the mounted Docker volume on the remote host
REMOTE_LOG_PATH = '/var/lib/docker/volumes/cowrie-data/_data/log/cowrie/cowrie.json'

# The local copy lives beside this script so app.py can find it
current_dir = os.path.dirname(os.path.abspath(__file__))
LOCAL_LOG_PATH = os.path.join(current_dir, 'hacker_data.json')


def sync_log():
    """Compare the remote and local log sizes and copy across whatever is new.

    Three cases are handled:
      remote > local  -> append only the new bytes (incremental pull)
      remote < local  -> the remote log was reset or rotated, so re-download it
      remote == local -> nothing new was captured, skip this round
    """
    try:
        # Open the SSH connection and an SFTP channel on top of it
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(VM_IP, port=VM_PORT, username=VM_USER, password=VM_PASS, timeout=15, banner_timeout=200)
        sftp = ssh.open_sftp()

        # How large is the log on the honeypot right now?
        try:
            remote_stat = sftp.stat(REMOTE_LOG_PATH)
            remote_size = remote_stat.st_size
        except IOError:
            print(f"[{time.strftime('%H:%M:%S')}] ERROR: {REMOTE_LOG_PATH} not found on the server. "
                  f"Check that the Docker container is running and has written a log.")
            sftp.close()
            ssh.close()
            return

        # How much of it do we already have locally?
        local_size = 0
        if os.path.exists(LOCAL_LOG_PATH):
            local_size = os.path.getsize(LOCAL_LOG_PATH)

        # Incremental sync: seek past what we already hold and append the rest
        if remote_size > local_size:
            print(f"[{time.strftime('%H:%M:%S')}] New data detected "
                  f"(remote: {remote_size}B > local: {local_size}B). Pulling the new bytes...")

            with sftp.open(REMOTE_LOG_PATH, 'rb') as remote_file:
                remote_file.seek(local_size)
                new_data = remote_file.read()

            with open(LOCAL_LOG_PATH, 'ab') as local_file:
                local_file.write(new_data)

            print(f"[{time.strftime('%H:%M:%S')}] Incremental sync complete. "
                  f"Pulled {len(new_data)} bytes of new log data.")

        # The remote file shrank, which means it was cleared or rotated.
        # An incremental append would corrupt the local copy, so start over.
        elif remote_size < local_size:
            print(f"[{time.strftime('%H:%M:%S')}] Remote log was reset or rotated (it is now smaller). "
                  f"Running a full re-sync...")
            sftp.get(REMOTE_LOG_PATH, LOCAL_LOG_PATH)
            print(f"[{time.strftime('%H:%M:%S')}] Full sync complete.")

        # Sizes match, so nothing was captured since the last check
        else:
            print(f"[{time.strftime('%H:%M:%S')}] No new honeypot data, skipping.")

        sftp.close()
        ssh.close()

    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] SSH / network connection failed: {e}")


if __name__ == '__main__':
    # Poll the honeypot forever; stop with Ctrl+C
    print("TAR Honeypot cloud log sync engine (Docker edition) started...")
    print(f"Monitoring DigitalOcean node: {VM_IP}:{VM_PORT}")
    while True:
        sync_log()
        time.sleep(15)
