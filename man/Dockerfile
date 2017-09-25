#FROM    golang:1.6.3-alpine
FROM    pub.f-road.com.cn/golang:1.6.3-alpine
RUN     echo 'http://mirrors.ustc.edu.cn/alpine/v3.4/main' > /etc/apk/repositories
RUN     apk add -U git bash curl gcc musl-dev tar  && mkdir -pv /manvendor/
COPY	man/glide-0.10.2-linux-amd64.tar.gz . 
RUN     tar -xf glide-0.10.2-linux-amd64.tar.gz linux-amd64/glide && \
        mv linux-amd64/glide /usr/bin/glide && \
        chmod +x /usr/bin/glide
COPY    man/glide.yaml /manvendor/
COPY    man/glide.lock /manvendor/
COPY    sys /manvendor/vendor/golang.org/x/sys 
WORKDIR /manvendor/
RUN     glide install && mv vendor src
ENV     GOPATH=$GOPATH:/go/src/github.com/docker/docker/vendor:/manvendor
RUN     go build -o /usr/bin/go-md2man github.com/cpuguy83/go-md2man

WORKDIR /go/src/github.com/docker/docker/
ENTRYPOINT ["man/generate.sh"]
