#!/usr/bin/env bash
# Build a local corpus of repos for exercising BlastRadius extraction.
#
# Six repos that share artifacts with each other, pinned inconsistently on
# purpose, and seeded with the extraction cases that are actually hard: stage
# aliases, ARG-templated bases, heredocs, registry ports, local module sources,
# workspace protocols, and a name that collides across two ecosystems.
#
#   ./make-fixtures.sh [target-dir]      (default: ~/br-fixtures)
set -euo pipefail

TARGET="${1:-$HOME/br-fixtures}"

if [[ -e "$TARGET" ]]; then
  echo "refusing to overwrite existing $TARGET" >&2
  echo "remove it first, or pass a different path" >&2
  exit 1
fi

mkdir -p "$TARGET"
cd "$TARGET"

new_repo() {
  mkdir -p "$1"
  git -C "$1" init -q
  git -C "$1" remote add origin "git@github.com:acme/$1.git"
}

finish() {
  git -C "$1" add -A
  git -C "$1" -c user.email=fixtures@acme.test -c user.name=Fixtures \
      commit -qm "initial fixture"
}

# ── 1. payments — Go service. Stage aliases and a SHA-pinned action. ──────────
new_repo payments
mkdir -p payments/.github/workflows payments/infra

cat > payments/Dockerfile <<'EOF'
# syntax=docker/dockerfile:1
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY . .
RUN go build -o /out/payments ./cmd/payments

FROM builder AS test
RUN go test ./...

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/payments /payments
ENTRYPOINT ["/payments"]
EOF

cat > payments/.github/workflows/ci.yml <<'EOF'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@f111f3307d8850f501ac008e886eec1fd1932a34
        with:
          go-version: '1.22'
      - uses: ./.github/actions/local-cache
      - name: Scan
        uses: docker://aquasec/trivy:0.50.1
EOF

cat > payments/infra/main.tf <<'EOF'
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"

  name = "payments"
  cidr = "10.0.0.0/16"
}

module "db" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 6.3"

  identifier = "payments-db"
}

module "shared_tags" {
  source = "./modules/tags"
}
EOF
finish payments

# ── 2. checkout — Node service. Range specs and an ecosystem collision. ──────
new_repo checkout
mkdir -p checkout/.github/workflows

cat > checkout/Dockerfile <<'EOF'
ARG BASE_IMAGE=node:20-bookworm-slim
FROM ${BASE_IMAGE} AS deps
WORKDIR /app
COPY package.json ./
RUN npm ci

FROM deps AS runtime
RUN <<SH
echo "not a real directive: FROM ghost:1.0"
SH
CMD ["node", "server.js"]
EOF

cat > checkout/package.json <<'EOF'
{
  "name": "@acme/checkout",
  "version": "2.4.0",
  "dependencies": {
    "express": "^4.19.2",
    "react": "^18.2.0",
    "lodash": "4.17.21",
    "redis": "~4.6.13",
    "@acme/shared-ui": "workspace:*",
    "left-pad": ">=1.3.0 <2.0.0",
    "patched-lib": "github:acme/patched-lib#v1.2.0"
  },
  "devDependencies": {
    "typescript": "5.4.5",
    "vitest": "*"
  }
}
EOF

cat > checkout/package-lock.json <<'EOF'
{
  "name": "@acme/checkout",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "@acme/checkout" },
    "node_modules/express": { "version": "4.21.2" },
    "node_modules/react": { "version": "18.3.1" },
    "node_modules/lodash": { "version": "4.17.21" },
    "node_modules/redis": { "version": "4.6.15" },
    "node_modules/typescript": { "version": "5.4.5" },
    "node_modules/vitest": { "version": "3.2.4" }
  }
}
EOF

cat > checkout/.github/workflows/deploy.yml <<'EOF'
name: deploy
on:
  workflow_dispatch:
jobs:
  ship:
    steps:
      - uses: actions/checkout@main
      - uses: actions/setup-node@v4
      - uses: acme/.github/.github/workflows/deploy.yml@v2
EOF
finish checkout

# ── 3. web — Frontend. Shares react and lodash with checkout. ────────────────
new_repo web
mkdir -p web/.github/workflows

cat > web/Dockerfile <<'EOF'
FROM node:20-alpine AS build
WORKDIR /app
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
EOF

cat > web/package.json <<'EOF'
{
  "name": "@acme/web",
  "dependencies": {
    "react": "18.3.1",
    "react-dom": "18.3.1",
    "lodash": "^4.17.20",
    "vite": "^5.2.0"
  }
}
EOF

# A lockfile: ^5.2.0 in the manifest, but 5.4.19 actually installed.
cat > web/package-lock.json <<'EOF'
{
  "name": "@acme/web",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "@acme/web" },
    "node_modules/react": { "version": "18.3.1" },
    "node_modules/react-dom": { "version": "18.3.1" },
    "node_modules/lodash": { "version": "4.17.21" },
    "node_modules/vite": { "version": "5.4.19" }
  }
}
EOF

cat > web/.github/workflows/ci.yml <<'EOF'
name: ci
jobs:
  test:
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v4
EOF
finish web

# ── 4. platform-infra — Terraform-heavy. Git sources and local modules. ─────
new_repo platform-infra
mkdir -p platform-infra/{network,compute,modules/tags,.github/workflows}

cat > platform-infra/network/main.tf <<'EOF'
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"
}

module "endpoints" {
  source  = "terraform-aws-modules/vpc/aws//modules/vpc-endpoints"
  version = ">= 5.0.0"
}

module "internal_dns" {
  source = "git::https://github.com/acme/tf-modules.git//dns?ref=v3.1.0"
}
EOF

cat > platform-infra/compute/main.tf <<'EOF'
module "asg" {
  source  = "terraform-aws-modules/autoscaling/aws"
  version = "7.4.1"
}

module "tags" {
  source = "../modules/tags"
}

module "eks" {
  source = "github.com/acme/tf-eks?ref=v1.9.0"
}
EOF

echo 'variable "env" { default = "prod" }' > platform-infra/modules/tags/main.tf

cat > platform-infra/.github/workflows/plan.yml <<'EOF'
name: plan
jobs:
  tf:
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
EOF
finish platform-infra

# ── 5. notifications — Helm chart and a registry with a port. ───────────────
new_repo notifications
mkdir -p notifications/chart notifications/.github/workflows

cat > notifications/chart/Chart.yaml <<'EOF'
apiVersion: v2
name: notifications
version: 0.3.1
dependencies:
  - name: redis
    version: 19.6.4
    repository: https://charts.bitnami.com/bitnami
  - name: kube-prometheus-stack
    version: "58.2.1"
    repository: https://prometheus-community.github.io/helm-charts
  - name: local-sidecar
    version: 0.1.0
    repository: file://../sidecar
EOF

cat > notifications/Dockerfile <<'EOF'
FROM registry.internal.acme.io:5000/base-python:3.11.9
WORKDIR /app
COPY . .
CMD ["python", "-m", "notifications"]
EOF

cat > notifications/package.json <<'EOF'
{
  "name": "@acme/notifications-cli",
  "dependencies": {
    "lodash": "^4.17.21",
    "commander": "~12.0.0"
  }
}
EOF

cat > notifications/.github/workflows/release.yml <<'EOF'
name: release
jobs:
  publish:
    steps:
      - uses: actions/checkout@v4
      - uses: azure/setup-helm@v4
EOF
finish notifications

# ── 6. legacy-cron — Everything floats. The worst-hygiene repo. ─────────────
new_repo legacy-cron
mkdir -p legacy-cron/.github/workflows

cat > legacy-cron/Dockerfile <<'EOF'
FROM alpine:latest
RUN apk add --no-cache curl
COPY run.sh /run.sh
CMD ["/run.sh"]
EOF

cat > legacy-cron/Dockerfile.worker <<'EOF'
FROM redis:latest
FROM ubuntu
RUN apt-get update
EOF

cat > legacy-cron/.github/workflows/nightly.yml <<'EOF'
name: nightly
jobs:
  run:
    steps:
      - uses: actions/checkout@main
      - uses: actions/cache@v3
EOF
finish legacy-cron

# ── Summary ─────────────────────────────────────────────────────────────────
cat <<EOF

Built 6 repos in $TARGET

  payments        go       stage aliases, SHA-pinned action, registry modules
  checkout        node     ARG base, heredoc, ranges, workspace protocol
  web             node     shares react + lodash with checkout
  platform-infra  tf       git:: sources, local modules, submodule paths
  notifications   helm     chart deps, registry-with-port image
  legacy-cron     shell    everything unpinned

Shared across repos, so the inject hook has something to say:
  actions/checkout   6 repos, pinned 4 different ways (v4 / v3 / main / SHA)
  lodash             3 repos, 3 different specs
  react              2 repos, ^18.2.0 vs 18.3.1
  terraform-aws-modules/vpc/aws   2 repos
  redis              docker image in legacy-cron, npm package in checkout
                     — the type-collision case

Next:
  cd $TARGET/payments && claude
  ...work, end the session, let the Stop hook fire...
  blastradius repos
  python3 $(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/grade.py

EOF
