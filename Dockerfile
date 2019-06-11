FROM ubuntu:19.04

RUN apt-get update -q && \
    apt-get install -qy  git make g++ autoconf libtool pkg-config bsdmainutils libboost-all-dev libssl-dev libevent-dev libdb++-dev && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean
WORKDIR /platinum
VOLUME /root/.platinumcoin/
ADD . /platinum
RUN ./autogen.sh && ./configure --with-gui=no --with-incompatible-bdb --enable-static --disable-shared && make -j4 && cp src/bitcoind /usr/local/bin/platinumd && cp src/bitcoin-cli /usr/local/bin/platinum-cli && make distclean
CMD ["platinumd"]
