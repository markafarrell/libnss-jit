FROM debian:trixie

COPY test/files/etc /etc

COPY target/release/libnss_jit.so /tmp/libnss_jit.so.2

COPY src/files/libnss-jit.sqlite /etc/libnss-jit/libnss-jit.sqlite

RUN install -m 0644 /tmp/libnss_jit.so.2 /lib && \
    /sbin/ldconfig -n /lib /usr/lib
