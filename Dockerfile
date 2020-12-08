FROM debian:stable-slim

# Install General Requirements
RUN apt-get update && apt-get install python3 python3-pip curl git -y

# Copy project content to /opt folder
#COPY . /opt/project...

# Install DNSTwist
RUN pip3 install dnstwist DNSPython whois

# Install Golang
RUN curl -O https://dl.google.com/go/go1.15.5.linux-amd64.tar.gz
RUN tar xvf go1.15.5.linux-amd64.tar.gz && chown -R root:root ./go && mv go /usr/local && rm -rf go1.15.5.linux-amd64.tar.gz

# Modify the PATH environment variable to include golang's path
ENV PATH $PATH:/usr/local/go/bin

# Install HTTProbe
RUN git clone https://github.com/tomnomnom/httprobe.git
RUN go build ./httprobe/main.go && mv main /bin/httprobe

# Uninstall setup tools and unused packages
RUN apt-get --purge remove curl git python3-pip -y && apt-get autoremove -y

# Install pkg as a python module
#RUN pip3 install /opt/project

# Entry point for docker (optional)
#ENTRYPOINT ["/opt/project/..."]
