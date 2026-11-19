# syntax=docker/dockerfile:1.7
#
# Commit image for ot-br-posix (OpenThread Border Router). Builds on the org C/C++ base image; adds the
# apt packages upstream's gtest suite needs, then runs mayhem/build.sh (fuzz harnesses + gtests) and
# mayhem/test.sh. Everything else the build uses is in the checkout: the git submodules (openthread with
# mbedtls, cJSON, cpp-httplib), which mayhem.yml's actions/checkout fetches recursively.
#
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile --build-arg COMMIT=$(git rev-parse HEAD) -t otbr .
#
# mayhem/Dockerfile.dockerignore replaces upstream's .dockerignore for this build (upstream's drops .git,
# which the commit image must carry).
FROM ghcr.io/savantenvs/base:20261023

ARG COMMIT
ARG REPO_URL
ARG SOURCE_DATE_EPOCH
ARG SANITIZER_FLAGS
ARG COVERAGE_FLAGS=
ARG MAYHEM_JOBS=

# googletest/googlemock for upstream's gtest suite (the functional oracle); jsoncpp for otbr-gtest-web,
# protobuf for otbr-gtest-telemetry (otbr-proto), libnftnl/libmnl for the nftables firewall tests.
USER root
RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true ; \
    apt-get update && apt-get install -yq --no-install-recommends libgtest-dev libgmock-dev \
       libjsoncpp-dev libprotobuf-dev protobuf-compiler libnftnl-dev libmnl-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*

USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN if [ -x /opt/mayhem/ccache/prefill ]; then /opt/mayhem/ccache/prefill bash mayhem/build.sh; \
    else bash mayhem/build.sh; fi

RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
