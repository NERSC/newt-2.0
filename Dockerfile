FROM ubuntu:latest
MAINTAINER Kelly L. Rowland <kellyrowland@lbl.gov>

RUN apt-get update && \
    apt-get install -y iputils-ping git vim && \
    apt-get install -y python3-pip python3-dev && \
    cd /usr/local/bin && \
    ln -s /usr/bin/python3 python && \
    pip3 install --upgrade pip

RUN git clone -b py3 https://github.com/NERSC/newt-2.0.git

WORKDIR /newt-2.0/

RUN pip install -r requirements.txt

RUN python manage.py migrate

EXPOSE 8080

ENTRYPOINT ["python", "manage.py"]
CMD ["runserver", "0.0.0.0:8080"]
