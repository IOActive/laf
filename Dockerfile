FROM golang:latest

RUN apt-get update && apt-get install -y python3-pip

# Set the working directory to /app
WORKDIR /root/app
ENV PYTHONPATH="/root/app" \
    GOPATH="/root/go"

# Add the python requirements first in order to docker cache them
ADD ./requirements.txt /root/app/requirements.txt

# Install any needed packages specified in requirements.txt
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt

# Copy the current directory contents into the container at /app
ADD . /root/app/

# Install go dependencies
RUN go get -d ./...

# Redirect python command to python3
RUN rm /usr/bin/python
RUN ln -s /usr/bin/python3 /usr/bin/python

# Compile go library
WORKDIR /root/app/lorawanwrapper/utils
RUN go build -o lorawanWrapper.so -buildmode=c-shared *.go

WORKDIR /root/app
CMD sleep infinity