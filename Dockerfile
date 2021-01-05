FROM python:3.8-slim
WORKDIR /usr/src/stsauth
COPY . .
RUN pip install .
ENTRYPOINT ["/usr/local/bin/stsauth"]
