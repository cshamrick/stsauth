FROM python:3.8-slim as build
WORKDIR /usr/src/stsauth
COPY . .
# hadolint ignore=DL3013
RUN apt-get update -y \
    && apt-get install --no-install-recommends -y git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir .[dist] \
    && python -m build

FROM python:3.8-slim as runtime
COPY --from=build /usr/src/stsauth/dist/*.whl /dist/
RUN pip install --no-cache-dir dist/stsauth*.whl

ENTRYPOINT ["stsauth"]