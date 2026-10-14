FROM rucio/rucio-clients:release-41.1.1 AS builder

WORKDIR /src

ARG SOURCE_REVISION
ARG PACKAGE_VERSION

ADD source.tar /src/

RUN python3 -m pip install --no-cache-dir build

# Generate version metadata inside the build, leaving the checkout unchanged.
RUN printf "IS_FINAL = False\nVERSION = '%s'\nBRANCH_NICK = 'rbac'\nREVISION_ID = '%s'\nREVNO = '0'\n" \
    "$PACKAGE_VERSION" "$SOURCE_REVISION" \
    > lib/rucio/vcsversion.py

# Use Rucio's own packaging workflow.
RUN bash tools/build_sdist_wheel.sh clients


FROM rucio/rucio-clients:release-41.1.1

ARG SOURCE_REVISION
LABEL org.opencontainers.image.revision="${SOURCE_REVISION}"

COPY --from=builder /src/dist/rucio_clients-*.whl /tmp/wheels/

RUN python3 -m pip install --no-cache-dir /tmp/wheels/*.whl \
    && python3 -m pip check \
    && rm -rf /tmp/wheels

# Repository for the RBAC tutorial
RUN dnf install -y git \
    && dnf clean all \
    && git clone https://gitlab.cern.ch/gguerrie/rucio-tutorial.git /opt/rucio-tutorial

# Setup of the certificate and configuration files with small script for setting the username at runtime.
COPY tls-ca-bundle.pem /certs/tls-ca-bundle.pem
COPY rucio.cfg /opt/rucio/etc/rucio.cfg
COPY --chmod=755 set-username.sh /usr/local/bin/set-username