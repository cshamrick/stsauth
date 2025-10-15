FROM python:3.9-slim AS build
# checkov:skip=CKV_DOCKER_3
# checkov:skip=CKV_DOCKER_2
WORKDIR /usr/src/stsauth
COPY . .
# hadolint ignore=DL3013
RUN apt-get update -y \
    && apt-get install --no-install-recommends -y git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir --group dist \
    && python -m build

FROM python:3.9-slim AS runtime
COPY --from=build /usr/src/stsauth/dist/*.whl /dist/
RUN pip install --no-cache-dir dist/stsauth*.whl

ENTRYPOINT ["stsauth"]