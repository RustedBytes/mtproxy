# Baseline Run Commands (from README.md)

1. `curl -s https://core.telegram.org/getProxySecret -o proxy-secret`
2. `curl -s https://core.telegram.org/getProxyConfig -o proxy-multi.conf`
3. `head -c 16 /dev/urandom | xxd -ps`
4. `./mtproto-proxy -u nobody -p 8888 -H 443 -S <secret> --aes-pwd proxy-secret proxy-multi.conf -M 1`
5. `wget localhost:8888/stats`
