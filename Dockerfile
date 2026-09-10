# Same binary. Streamable HTTP MCP. Not a Worker.
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/password-manager ./cmd/password-manager

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/password-manager /password-manager
VOLUME ["/data"]
ENV PWM_HOME=/data
ENV PWM_MCP_URL=https://pwm.vortex.nyc/mcp
EXPOSE 4461
ENTRYPOINT ["/password-manager"]
CMD ["mcp", "--listen", "0.0.0.0:4461", "--url", "https://pwm.vortex.nyc/mcp"]
