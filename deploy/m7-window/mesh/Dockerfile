# Builds the tiny M7 mesh service (deploy/m7-window/mesh). Context is the repo
# root so the module (go.mod) is available. Static, distroless — host-networked.
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /mesh ./deploy/m7-window/mesh

FROM gcr.io/distroless/static-debian12
COPY --from=build /mesh /mesh
ENTRYPOINT ["/mesh"]
