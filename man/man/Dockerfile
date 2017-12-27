#FROM    golang:1.6.3-alpine
FROM    pub.f-road.com.cn/golang:1.6.3-alpine
RUN     echo 'http://mirrors.ustc.edu.cn/alpine/v3.4/main' > /etc/apk/repositories
RUN     apk add -U git bash curl gcc musl-dev tar  && mkdir -pv /manvendor/
WORKDIR /manvendor/
COPY    src.tgz /manvendor/
RUN     tar -xf src.tgz 
ENV     GOPATH=$GOPATH:/go/src/github.com/docker/docker/vendor:/manvendor
RUN     go build -o /usr/bin/go-md2man github.com/cpuguy83/go-md2man

WORKDIR /go/src/github.com/docker/docker/
ENTRYPOINT ["man/generate.sh"]
