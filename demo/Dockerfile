FROM ubuntu:20.04
ENV METEMCYBER_HOST_ADDR=0.0.0.0

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y \
  software-properties-common

RUN add-apt-repository ppa:ethereum/ethereum
RUN ( \
  apt-get update && apt-get install -y \
  python3.8 \
  python3-pip \
  python3-gdbm \
  && cd /usr/local/bin \
  && ln -s /usr/bin/python3 python \
  && pip3 install --upgrade pip \
  ) || exit 255

COPY requirements.txt ./
COPY requirements/ ./requirements/
RUN pip install --no-cache-dir -r requirements.txt
