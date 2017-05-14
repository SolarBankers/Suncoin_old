#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "suncoin binary dir:" "$DIR"

pushd "$DIR" >/dev/null

go run cmd/suncoin/suncoin.go --gui-dir="${DIR}/src/gui/static/" $@

popd >/dev/null
