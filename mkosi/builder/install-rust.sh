#!/usr/bin/env bash

set -euo pipefail

curl -sSf https://sh.rustup.rs | bash -s -- -y --default-toolchain 1.95.0
