# E1 dynamic-trace environment: redis 7.4 (glibc 2.36) + Debian's qemu-user
# 7.2 (built with plugin support) + the qemu-plugin.h taken from the exact
# Debian source version of the installed qemu-user.
FROM redis:7.4-bookworm

RUN sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/debian.sources \
 && apt-get update \
 && apt-get install -y --no-install-recommends qemu-user gcc libc6-dev dpkg-dev xz-utils \
 && src_ver="$(dpkg-query -W -f='${source:Version}' qemu-user)" \
 && mkdir -p /tmp/qsrc /opt/qemu-plugin && cd /tmp/qsrc \
 && apt-get source --download-only "qemu=${src_ver}" \
 && tar -xJf qemu_*.orig.tar.xz --wildcards '*/include/qemu/qemu-plugin.h' \
 && find . -name qemu-plugin.h -exec cp {} /opt/qemu-plugin/ \; \
 && test -f /opt/qemu-plugin/qemu-plugin.h \
 && echo "${src_ver}" > /opt/qemu-plugin/SOURCE_VERSION \
 && cd / && rm -rf /tmp/qsrc /var/lib/apt/lists/*
