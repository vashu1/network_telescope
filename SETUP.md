### Create droplet

Basic

Regular Intel with SSD   - cheapest

IPv6 check

Password

###### update
    apt-get update
    apt upgrade -y

###### ssh on 222
    echo Port 222 >> /etc/ssh/sshd_config
    service ssh restart

###### accept all tcp except 22, 222
    iptables -A INPUT -p tcp --dport 1:65389 -j ACCEPT
    siptables -t nat -A PREROUTING -p tcp --dport 1:21 -j REDIRECT --to-port 5001
    iptables -t nat -A PREROUTING -p tcp --dport 23:221 -j REDIRECT --to-port 5001
    iptables -t nat -A PREROUTING -p tcp --dport 223:65389 -j REDIRECT --to-port 5001
    iptables -F
    
    apt install ncat -y
    screen
    while :; do timeout 300 ncat --keep-open --listen -p 5001 ; done

###### save tcp/udp traffic to pcaps
    screen
    tcpdump -s 0 -i eth0 -w /root/network_telescope_9.pcap
    tcpdump ip6 -s 0 -i eth0 -w /root/network_telescope_V6_9.pcap

###### save tcp/ssh-honeypot
    git clone https://github.com/droberson/ssh-honeypot
    apt install libssh-dev libjson-c-dev -y
    apt install build-essential -y
    apt install clang -y
    cd ssh-honeypot
    make
    ssh-keygen -t rsa -f ssh-honeypot.rsa
    bin/ssh-honeypot -r ./ssh-honeypot.rsa -l ../ssh_passwords -j ../ssh_passwords.json -d
    cd ..

