
# docker buildx create --name pulsebuilder --use --bootstrap --buildkitd-config .buildkitd.toml
# docker buildx build --push --platform linux/amd64,linux/arm64 --tag truenas:30095/pulse/pulse:dev .

FROM --platform=$BUILDPLATFORM golang:1.25.3 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY . .

RUN echo "pulse:x:42756:" >> /etc/group \
    && echo "pulse:x:42756:42756:pulse:/var/pulse:/bin/false" >> /etc/passwd \
    && echo "pulse:*:::::::" >> /etc/shadow

RUN mkdir /tmp/root-fs \
    && touch /tmp/root-fs/$TARGETOS.$TARGETARCH \
    && mkdir /tmp/root-fs/etc \
      && cp -p /etc/group /tmp/root-fs/etc/group \
      && cp -p /etc/passwd /tmp/root-fs/etc/passwd \
      && cp -p /etc/shadow /tmp/root-fs/etc/shadow \
      && mkdir /tmp/root-fs/etc/pulse && chown pulse:pulse /tmp/root-fs/etc/pulse \
    && mkdir /tmp/root-fs/var \
      && mkdir /tmp/root-fs/var/pulse && chown pulse:pulse /tmp/root-fs/var/pulse \
    && mkdir /tmp/root-fs/bin

RUN go mod download

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /tmp/root-fs/bin/pulse cmd/pulse/*.go

FROM scratch

COPY --from=builder /tmp/root-fs/ /

USER pulse
CMD ["/bin/pulse"]
