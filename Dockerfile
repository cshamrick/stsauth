FROM python:3.8-slim
RUN useradd --create-home --shell /bin/bash stsauth
WORKDIR /home/stsauth
USER stsauth
COPY . .
RUN pip install .
ENTRYPOINT ["/home/stsauth/.local/bin/stsauth"]
