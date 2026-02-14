# game bridge

if you can't port forward but you have a crappy VPS you can SSH into, you can force the UDP traffic through SSH port forwarding with this!

## example:

### for factorio:

1. on the machine that hosts game server:

    `python3 main.py --server -P 34197 -p 12345`


2. ssh to your vps:

    `ssh -R 12345:localhost:12345 user@address`


3. on the vps:

    `python3 main.py -P 34197 -p 12345`


4. allow 34197/udp on vps
5. enjoy!