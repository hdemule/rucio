FROM rucio/rucio-clients:release-41.1.1 AS builder

USER root
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

USER root

ARG SOURCE_REVISION
LABEL org.opencontainers.image.revision="${SOURCE_REVISION}"

COPY --from=builder /src/dist/rucio_clients-*.whl /tmp/wheels/

RUN python3 -m pip install --no-cache-dir /tmp/wheels/*.whl \
    && python3 -m pip check \
    && rm -rf /tmp/wheels

# Preserve the official image's entrypoint and default command.