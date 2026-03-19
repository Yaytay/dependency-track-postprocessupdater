FROM gcr.io/distroless/static-debian12:nonroot

COPY dependency-track-postprocessupdater /usr/local/bin/dependency-track-postprocessupdater

EXPOSE 9916

ENTRYPOINT ["/usr/local/bin/dependency-track-postprocessupdater"]