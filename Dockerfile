# PRCY DEPS IMG
FROM ubuntu:18.04

COPY ./prcycoin.conf /root/.prcycoin/prcycoin.conf

COPY . /prcycoin
WORKDIR /prcycoin

RUN apt-get update
RUN apt-get install -y build-essential libtool bsdmainutils autotools-dev autoconf pkg-config automake python3
RUN apt-get install -y libssl1.0-dev libzmq5 libgmp-dev libevent-dev libboost-all-dev libsodium-dev cargo
RUN apt-get install -y libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools libprotobuf-dev protobuf-compiler libqrencode-dev
RUN apt-get install -y software-properties-common g++-multilib binutils-gold patch
RUN add-apt-repository ppa:pivx/pivx
RUN apt-get update
RUN apt-get install -y libdb4.8-dev libdb4.8++-dev
RUN ./autogen.sh
RUN ./configure --disable-jni --disable-tests --disable-gui-tests --disable-bench
RUN make
RUN make install
EXPOSE 59682 59683 59684 59685s
CMD ["prcycoind", "--printtoconsole"]
