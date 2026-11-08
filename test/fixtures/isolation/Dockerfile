FROM golang:1.26.10@sha256:cfa27959837144bf4649802ba38e59daffd0dd2a7994aa83daaf113285b0f551 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY test/fixtures/isolation/main.go test/fixtures/isolation/main.go
RUN CGO_ENABLED=0 go build -tags=e2e -o /fixture ./test/fixtures/isolation
FROM scratch
COPY --from=build /fixture /fixture
# Mirrors the recommended celld packaging for krun (FINDINGS.md section 4).
STOPSIGNAL SIGINT
USER 10001:10001
ENTRYPOINT ["/fixture"]
