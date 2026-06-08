FROM python:3.12-alpine

RUN apk add --no-cache bash curl iputils busybox-extras

WORKDIR /lab
COPY scripts/attack_demo.sh /lab/attack_demo.sh
COPY service.py /lab/service.py

EXPOSE 8090
CMD ["python", "/lab/service.py"]
