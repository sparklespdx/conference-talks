#/usr/bin/env python2
import nmap
import sys
import json
import docker


target = sys.argv[1]
nm = nmap.PortScanner()

nm.scan(target, '2375', arguments='-sT')

port_open = []
pwned_hosts = []


for h in nm.all_hosts():
    if nm[h]['tcp'][2375]['state'] != 'filtered' and nm[h]['tcp'][2375]['state'] != 'closed':
        port_open.append(h)

print("Checking: " + str(port_open))


for h in port_open:
    print h
    host = {}
    host['ip'] = h
    try:
        cli = docker.APIClient(h + ':2375', version='auto', timeout=5)
        host['pinged'] = cli.ping()
        host['containers'] = cli.containers()
        host['docker_version'] = cli.version()
        host['responded'] = True
    except:
        host['responded'] = False

    pwned_hosts.append(host)


with open(target.replace('/', '--') + '_vulnerable.json', 'w') as f:
    f.write(json.dumps(pwned_hosts))
