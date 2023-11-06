import os
import re

tcp_states = {
    '00': 'UNKNOWN',
    '01': 'ESTABLISHED',
    '02': 'SYN_SENT',
    '03': 'SYN_RECV',
    '04': 'FIN_WAIT1',
    '05': 'FIN_WAIT2',
    '06': 'TIME_WAIT',
    '07': 'CLOSE',
    '08': 'CLOSE_WAIT',
    '09': 'LAST_ACK',
    '0A': 'LISTEN',
    '0B': 'CLOSING'
}

def ip_hex_to_dec(hex_ip):
    """ Convertit une adresse IP en hexadécimal en décimal pointé. """
    ip = [(hex_ip[i:i+2]) for i in range(0, len(hex_ip), 2)]
    return '.'.join(str(int(part, 16)) for part in reversed(ip))

def get_inode_to_process_mapping():
    """ Retourne une correspondance entre inodes et informations de processus. """
    inode_to_process = {}
    for pid in os.listdir('/proc'):
        if pid.isdigit():
            fd_dir = f'/proc/{pid}/fd'
            cmdline_path = f'/proc/{pid}/cmdline'
            try:
                with open(cmdline_path, 'r') as cmdline_file:
                    cmdline = cmdline_file.read().replace('\x00', ' ').strip()
                for fd in os.listdir(fd_dir):
                    fd_path = os.path.join(fd_dir, fd)
                    if os.path.islink(fd_path):
                        inode = os.readlink(fd_path)
                        if inode.startswith('socket:'):
                            inode_key = inode.split('[')[1][:-1]
                            inode_to_process[inode_key] = cmdline
            except OSError:
                pass
    return inode_to_process

def convert_line(line, inode_to_process):
    """ Convertit une ligne du fichier /proc/net/tcp en valeurs lisibles. """
    parts = re.split(r'\s+', line.strip())
    local_ip, local_port = parts[1].split(':')
    remote_ip, remote_port = parts[2].split(':')
    inode = parts[9]
    cmdline = inode_to_process.get(inode, None)

    return {
        'local_ip': ip_hex_to_dec(local_ip),
        'local_port': int(local_port, 16),
        'remote_ip': ip_hex_to_dec(remote_ip),
        'remote_port': int(remote_port, 16),
        'status': tcp_states[parts[3]],
        'cmdline': cmdline
    }

inode_to_process = get_inode_to_process_mapping()
with open('/proc/net/tcp', 'r') as f:
    lines = f.readlines()[1:]

connections = [convert_line(line, inode_to_process) for line in lines]

for conn in connections:
    print(f"Local Address: {conn['local_ip']}:{conn['local_port']}, "
          f"Remote Address: {conn['remote_ip']}:{conn['remote_port']}, "
          f"Status: {conn['status']}, "
          f"Command Line: {conn['cmdline']}")


