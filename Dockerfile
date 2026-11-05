FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/server ./cmd/server && mkdir /data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/server /server
COPY --from=build --chown=65532:65532 /data /data
EXPOSE 8081
ENTRYPOINT ["/server"]
