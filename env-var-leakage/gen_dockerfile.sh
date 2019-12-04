#!/bin/bash

echo "FROM alpine"
echo "RUN apk add curl bash"
echo "COPY app /app"

while read -r line; do
    line_lc=$(echo -n "$line" | tr 'A-Z' 'a-z')
    echo "ARG $line"
    echo "ARG $line_lc"
done <<< "$(cat $1)"

echo "RUN bash /app/build.sh"
echo "CMD [\"/app/build.sh\"]"

