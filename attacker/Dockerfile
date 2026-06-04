FROM alpine:3.20

RUN apk add --no-cache bash curl iputils busybox-extras

WORKDIR /lab
COPY scripts/attack_demo.sh /lab/attack_demo.sh

CMD ["sleep", "infinity"]
