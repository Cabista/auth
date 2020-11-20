FROM golang:1.15-alpine AS build

RUN mkdir /app

COPY . /app

WORKDIR /app

RUN go build -o main .

FROM alpine:3.12

COPY --from=build /app/main /
COPY --from=build /app/private.pem /private.pem

CMD ["/main"]