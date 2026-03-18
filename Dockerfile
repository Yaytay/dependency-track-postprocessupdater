FROM gcr.io/distroless/static-debian12:nonroot

COPY dependency-track-exporter /usr/local/bin/dependency-track-exporter

EXPOSE 9916

ENTRYPOINT ["/usr/local/bin/dependency-track-exporter"]