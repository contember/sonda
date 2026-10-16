FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sonda-server ./cmd/sonda-server \
    && mkdir /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sonda-server /sonda-server
# The default database path sonda.db resolves here; mount a volume to keep the audit log.
COPY --from=build --chown=nonroot:nonroot /out/data /data
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["/sonda-server"]
CMD ["serve", "-c", "/etc/sonda/sonda.yaml"]
