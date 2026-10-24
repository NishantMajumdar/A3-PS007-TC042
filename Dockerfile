FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV DISPLAY=:0

# Install Open vSwitch, Mininet, radvd, networking tools, and Python dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openvswitch-switch \
    openvswitch-common \
    mininet \
    radvd \
    ethtool \
    iproute2 \
    iptables \
    net-tools \
    procps \
    psmisc \
    python3 \
    python3-pip \
    python3-scapy \
    python3-flask \
    xterm \
    x11-xserver-utils \
    xauth \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy all project code
COPY . /app

# Grant execution rights to entrypoint script
RUN chmod +x /app/docker-entrypoint.sh

# Expose ports for Web SOC UI and WebSocket stream
EXPOSE 5000 8765

ENTRYPOINT ["/app/docker-entrypoint.sh"]
