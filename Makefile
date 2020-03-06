SHORT_NAME = opa-firewall
IMAGE = cainelli/opa-firewall
DEV_TAG = 1.0.0-dev
GOOS ?= linux
GOARCH ?= amd64
REV = $(shell git rev-parse --short HEAD)
VERSION = $(shell echo $(BUILD_VERSION))
CURRENTPATH = $(shell echo $(PWD))

build-local:
	go build -ldflags "-X main.VERSION=${VERSION}" -o ${SHORT_NAME} cmd/main.go

build:
	env GOOS=${GOOS} GOARCH=${GOARCH} go build -ldflags "-X main.VERSION=${VERSION}" -o ${SHORT_NAME} cmd/main.go

image-build:
	docker build --build-arg BUILD_VERSION="1.0.0-dev" . -f Dockerfile -t ${IMAGE}:${DEV_TAG}

image-push:
	docker push ${IMAGE}:${DEV_TAG}

up:
	docker-compose stop && docker-compose up

clean:
	docker-compose stop && docker-compose rm
