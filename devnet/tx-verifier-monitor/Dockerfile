FROM alpine:latest

RUN apk add --no-cache inotify-tools

COPY monitor.sh /monitor.sh
RUN chmod +x /monitor.sh

CMD ["/monitor.sh"]
