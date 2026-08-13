FROM internetsystemsconsortium/bind9:9.20

COPY named.conf /etc/bind/named.conf
COPY db.example.com db.open.com /var/lib/bind/

RUN chown -R bind:bind /var/lib/bind /etc/bind
