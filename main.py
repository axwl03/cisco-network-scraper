from pwn import *
import sys, re, networkx, json
from getpass import getpass
from telnetlib import Telnet

adjList = {}
username, password = '', ''

def extractSwitchName(data):
    return re.search(r'(?<=\n).*?(?=>|#)', data).group(0)

def parseCdpNeighbor(data):
    neighbors = []
    blockPattern = re.compile(r'(?<=Device ID: ).*?(?=-----|\Z)', flags=re.DOTALL)
    ipPattern = re.compile(r'(?<=IP address: ).*')
    interfacePattern = re.compile(r'(?<=Interface: ).*?(?=, )')
    portIdPattern = re.compile(r'(?<=Port ID \(outgoing port\): ).*(?=\r)')
    blocks = blockPattern.findall(data)
    for block in blocks:
        node = {}
        result = block.partition('\r\n')
        node['device_id'] = result[0]
        node['ip_address'] = ipPattern.search(block).group(0).strip()
        node['interface'] = interfacePattern.search(block).group(0)
        node['port_id'] = portIdPattern.search(block).group(0)
        neighbors.append(node)
    return neighbors

def printList():
    for node in adjList:
        log.info(node + ' -> ' + ', '.join(map(lambda neighbor: neighbor['device_id'], adjList[node])))

def canConnect(ip):
    try:
        with Telnet(ip, 23, 1) as tn:
            pass
    except:
        return False
    else:
        return True

def search(io):
    # authentication
    d = io.recvuntil(b'Username: ')
    io.sendline(username.encode('utf-8'))
    d = io.recvuntil(b'Password: ')
    io.sendline(password.encode('utf-8'))

    # output all lines
    io.sendline(b'terminal length 0')
    
    # find current switch name
    data = io.recvregex(b'>|#').decode('utf-8')
    switchName = extractSwitchName(data)

    # cut neighbor entries
    io.sendline(b'show cdp neighbors detail')
    io.recvuntil(b'Device ID: ')
    data = io.recvregex(switchName.encode('utf-8') + b'>|#', timeout=1).decode('ascii')
    if data == '':
        # no neighbors
        log.warn(switchName + ': no neighbor')
        adjList[switchName] = []
        return
    data = 'Device ID: ' + data
    neighbors = parseCdpNeighbor(data)
    io.close()

    # Add to adjList
    if switchName not in adjList:
        adjList[switchName] = neighbors

    for neighbor in neighbors:
        if neighbor['device_id'] not in adjList and canConnect(neighbor['ip_address'].encode('utf-8')):
            try:
                io = process(['telnet', neighbor['ip_address']])
                search(io)
            except:
                log.warn('CMD: telnet ' + neighbor['ip_address'] + ' failed')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        log.warn('Usage: python main.py <ip_address>')
        sys.exit(1)

    username, password = input('Username: ').strip(), getpass().strip()

    # use telnet to connect to the switch
    io = process(['telnet', sys.argv[1]])

    search(io)
    printList()
    with open('networkLayout.json', 'w') as f:
        f.write(json.dumps(adjList))
