$TTL 300
@       IN      SOA     ns1.open.com. admin.open.com. (
                        1       ; serial
                        3600    ; refresh
                        600     ; retry
                        86400   ; expire
                        300 )   ; negative TTL
@       IN      NS      ns1.open.com.
ns1     IN      A       127.0.0.1
home    IN      A       127.0.0.1
