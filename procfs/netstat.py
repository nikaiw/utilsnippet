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

def convert_line(line):
    """ Convertit une ligne du fichier /proc/net/tcp en valeurs lisibles. """
    parts = re.split(r'\s+', line.strip())
    local_ip, local_port = parts[1].split(':')
    remote_ip, remote_port = parts[2].split(':')

    return {
        'local_ip': ip_hex_to_dec(local_ip),
        'local_port': int(local_port, 16),
        'remote_ip': ip_hex_to_dec(remote_ip),
        'remote_port': int(remote_port, 16),
        'status': tcp_states[parts[3]]
    }

with open('/proc/net/tcp', 'r') as f:
    lines = f.readlines()[1:]

connections = [convert_line(line) for line in lines]

for conn in connections:
    print(f"Local Address: {conn['local_ip']}:{conn['local_port']}, "
          f"Remote Address: {conn['remote_ip']}:{conn['remote_port']}, "
          f"Status: {conn['status']}")

