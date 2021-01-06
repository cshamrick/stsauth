FROM python:3.8 as build

RUN pip install git+https://github.com/rokm/pyinstaller.git@bootloader-process-name staticx
RUN apt-get update && apt-get install patchelf

WORKDIR /usr/src/stsauth
COPY . .
RUN pip install .
RUN pyinstaller sts_auth/cli.py -F --clean --add-data sts_auth/__init__.py:. -n stsauth \
    && staticx dist/stsauth dist/stsauth_static \
    && mkdir dist/empty

FROM alpine:latest as base
ENV MUSL_LOCALE_DEPS cmake make musl-dev gcc gettext-dev libintl
ENV MUSL_LOCPATH /usr/share/i18n/locales/musl

RUN apk add --no-cache \
    $MUSL_LOCALE_DEPS \
    && wget https://gitlab.com/rilian-la-te/musl-locales/-/archive/master/musl-locales-master.zip \
    && unzip musl-locales-master.zip \
    && cd musl-locales-master \
    && cmake -DLOCALE_PROFILE=OFF -D CMAKE_INSTALL_PREFIX:PATH=/usr . && make && make install \
    && cd .. && rm -r musl-locales-master

FROM base
COPY --from=build /usr/src/stsauth/dist/stsauth_static /stsauth
COPY --from=build /usr/src/stsauth/dist/empty /tmp
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENTRYPOINT ["/stsauth"]