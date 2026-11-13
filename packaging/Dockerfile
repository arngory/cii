FROM scratch
ARG TARGETARCH
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY cii-linux-${TARGETARCH} /cii
WORKDIR /tmp
WORKDIR /data
ENV HOME=/data
ENTRYPOINT ["/cii"]
