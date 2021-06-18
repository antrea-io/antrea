FROM golang:alpine as build
RUN mkdir /netpol
ADD ./ /netpol
WORKDIR /netpol
RUN  go build -o main pkg/main/main.go

FROM alpine
COPY --from=build /netpol/main /netpol
CMD ["/netpol"]
