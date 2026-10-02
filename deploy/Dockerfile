# The uspace-ansp Go image: the three processes as /api,
# /manned-adapter and /manned-feed; the compose service overrides the
# entrypoint. Built in CI, never on a server (docs/PLAN.md section 11).
#
#   docker build -f deploy/Dockerfile --build-arg VERSION=$(git describe --always) .

FROM golang:1.27 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
# The goose trees, embedded into the binaries (package migrations).
COPY migrations ./migrations
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    for p in api manned-adapter manned-feed; do \
      go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "/out/${p}" "./cmd/${p}" || exit 1; \
    done

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/ /
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/api"]
