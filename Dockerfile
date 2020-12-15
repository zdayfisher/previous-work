FROM debian:stable-slim

# Install Requirements for setup
RUN apt-get update && \
    apt-get install build-essential zlib1g-dev libncurses5-dev libgdbm-dev \
    libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev \
    wget libbz2-dev liblzma-dev curl python3-pip git python3-dev automake autoconf libtool -y

# Download and build Python 3.8.5
RUN wget https://www.python.org/ftp/python/3.8.5/Python-3.8.5.tgz && tar -xf Python-3.8.5.tgz
RUN cd Python-3.8.5 && ./configure --enable-optimizations && make && make install .
RUN cd .. && rm -rf Python-3.8.5 && rm Python-3.8.5.tgz

# Install Golang
RUN curl -O https://dl.google.com/go/go1.15.5.linux-amd64.tar.gz
RUN tar xvf go1.15.5.linux-amd64.tar.gz && chown -R root:root ./go && mv go /usr/local && rm -rf go1.15.5.linux-amd64.tar.gz

# Modify the PATH environment variable to include golang's path
ENV PATH $PATH:/usr/local/go/bin

# Install HTTProbe
RUN git clone https://github.com/tomnomnom/httprobe.git
RUN go build ./httprobe/main.go && mv main /bin/httprobe

# Clone and install crtsh
RUN git clone https://github.com/PaulSec/crt.sh && pip3 install crt.sh/. && rm -rf crt.sh

# Copy PhishFinder, install as Python module, Remove source files
COPY . /opt/phishfinder
RUN pip3 install -r /opt/phishfinder/requirements.txt && \
    pip3 install /opt/phishfinder/. && \
    rm -rf /opt/phishfinder

# Install ssdeep
RUN BUILD_LIB=1 pip3 install ssdeep

# Uninstall setup tools and unused packages
RUN apt-get --purge remove curl git python3-pip build-essential zlib1g-dev \
    libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev \
    libsqlite3-dev liblzma-dev wget libbz2-dev -y && apt-get autoremove -y

# Entry point for Docker
ENTRYPOINT ["phishfinder"]
