FROM python:3.8 AS build
WORKDIR /usr/src/stsauth
COPY . .
RUN pip install .
RUN pip install pyinstaller && pyinstaller sts_auth/cli.py -F --clean --add-data sts_auth/__init__.py:. -n stsauth

FROM scratch
COPY --from=build /usr/src/stsauth/dist/stsauth /
ENTRYPOINT ["/stsauth"]
