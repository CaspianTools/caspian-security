# Synthetic Dockerfile fixture for the vulnerable-corpus regression test.
# Every issue here is deliberate.

# DOCKER001 — base image pinned to :latest
FROM node:latest

# DOCKER003 — secret baked into the image layer
ENV DATABASE_PASSWORD=supersecret123

# DOCKER004 — ADD from a remote URL without checksum verification
ADD https://example.com/install.sh /tmp/install.sh

# DOCKER007 — curl piped into sh
RUN curl -fsSL https://example.com/setup | sh

# DOCKER006 — apt-get install without --no-install-recommends and no pin
RUN apt-get install -y python3

# DOCKER002 — no USER directive, container runs as root
CMD ["node", "server.js"]
