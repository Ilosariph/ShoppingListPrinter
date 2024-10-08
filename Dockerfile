FROM python:3.12-slim

WORKDIR /python-docker

COPY python/requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY /python .

CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0"]
