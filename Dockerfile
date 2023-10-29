FROM ubuntu

RUN apt-get update && apt-get install -y --no-install-recommends --no-install-suggests wget vim  \ 
    libboost-all-dev ca-certificates software-properties-common \
    git sudo make gcc g++ valgrind cmake python3 

RUN mkdir /test
COPY openfhe_demo /test/openfhe_demo
WORKDIR /test
# COPY SEAL /test/SEAL
RUN git clone https://github.com/openfheorg/openfhe-development
WORKDIR /test/openfhe-development
RUN mkdir build
WORKDIR /test/openfhe-development/build
RUN cmake ..
RUN make -j4
RUN make install
# RUN cmake -S . -B build
# RUN cmake --build build
# RUN sudo cmake --install build

WORKDIR /test/openfhe_demo
RUN cmake -S . -B build
RUN cmake --build build
RUN make 

WORKDIR /test/openfhe_demo