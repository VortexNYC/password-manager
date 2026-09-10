# Same binary. Streamable HTTP MCP. Not a Worker.
# No VOLUME: Railway rejects it. Vault is a Railway volume mounted at /data.
# Distroless has no shell. Do not put $PORT in CMD — mcp binds os.Getenv("PORT").
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/password-manager ./cmd/password-manager

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/password-manager /password-manager
ENV PWM_HOME=/data
EXPOSE 4461
ENTRYPOINT ["/password-manager"]
CMD ["mcp"]
