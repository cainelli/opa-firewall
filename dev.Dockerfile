FROM golang:1.13-alpine

RUN apk add git

RUN go get -u github.com/cosmtrek/air

RUN apk add pkgconfig \
      bash              \
      gcc			\
      git 			\
      librdkafka-dev    \
      libressl-dev      \
      musl-dev          \
      dep               \
      zlib-dev


ENV PKG_CONFIG_PATH="${PKG_CONFIG_PATH}:/usr/lib/"

ENTRYPOINT [ "/go/bin/air" ]
