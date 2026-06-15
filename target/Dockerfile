FROM python:3.12-alpine

RUN apk add --no-cache iproute2 procps findutils

WORKDIR /app
COPY app/server.py /app/server.py

RUN mkdir -p /var/log/unix-cyber-lab /lab /opt /srv \
    && printf 'normal\n' > /lab/service.conf \
    && chmod 0666 /lab/service.conf

EXPOSE 8080
CMD ["python", "/app/server.py"]
