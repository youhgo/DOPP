#syntax=docker/dockerfile:1
FROM python:3.10-slim-buster
WORKDIR /python-docker
RUN apt-get update && apt-get install -y nano python-dev
COPY docker_files/requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY . .
CMD [ "python3",  "dopp_server.py"]



