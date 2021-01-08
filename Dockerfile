FROM python:3.8 as build
WORKDIR /usr/src/stsauth
COPY . .
RUN pip install pyinstaller==4.0 staticx . \
    && apt-get update \
    && apt-get install patchelf \
    && pyinstaller sts_auth/cli.py -F --clean --add-data sts_auth/__init__.py:. -n stsauth \
    && staticx dist/stsauth dist/stsauth_static

FROM ubuntu:latest
COPY --from=build /usr/src/stsauth/dist/stsauth_static /stsauth
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENTRYPOINT ["/stsauth"]