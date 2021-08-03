FROM python:3.8 as build
WORKDIR /usr/src/stsauth
COPY . .
RUN pip install .[dist] \
    && python -m build

FROM python:3.8 as runtime
COPY --from=build /usr/src/stsauth/dist/*.whl /dist/
RUN pip install dist/stsauth*.whl

ENTRYPOINT ["stsauth"]