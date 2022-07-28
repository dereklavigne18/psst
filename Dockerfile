FROM library/python:3.9.0

RUN mkdir /setup
COPY ./requirements.txt /setup

RUN pip install -r /setup/requirements.txt