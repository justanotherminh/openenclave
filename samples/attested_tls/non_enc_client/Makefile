# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../config.mk

.PHONY: all build clean run

all: build

CFLAGS=$(shell pkg-config oehost-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --libs)

all: build

build:
	$(CXX) -g -c $(CXXFLAGS) -std=c++11 -I. -I/usr/include/openssl client.cpp cert_verify_config.cpp ../common/verify_callback.cpp
	$(CXX) -o tls_non_enc_client client.o cert_verify_config.o verify_callback.o $(LDFLAGS)

clean:
	rm -f tls_non_enc_client *.o ../cert.der

run:
	./tls_non_enc_client -server:localhost -port:12341
