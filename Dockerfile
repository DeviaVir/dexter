FROM golang:alpine as build-env

ENV GO111MODULE=on
ENV USER=root
WORKDIR /go/src/app
ADD . /go/src/app

RUN apk add make git build-base \
 && go mod vendor \
 && make

FROM golang:alpine
COPY --from=build-env /go/src/app/build/dexter_linux_amd64 /dexter
CMD ["/dexter"]
