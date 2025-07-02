# Use official Go base image with Python and Linux tools
FROM golang:1.21-buster

# Install system dependencies: Python, pip, Git, curl
RUN apt-get update && \
    apt-get install -y python3 python3-pip curl git && \
    apt-get clean

# Set Go environment variables
ENV GOPATH=/go
ENV PATH=$PATH:$GOPATH/bin

# Create Go binary path
RUN mkdir -p "$GOPATH/bin"

# Install recon tools via Go
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/projectdiscovery/alterx/cmd/alterx@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/tomnomnom/qsreplace@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    cp "$GOPATH/bin/"* /usr/local/bin/

# Set working directory
WORKDIR /app

# Copy your app code into the container
COPY . .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Expose port (Flask default)
EXPOSE 5000

# Start your Flask app using Gunicorn
CMD ["gunicorn", "-b", "0.0.0.0:5000", "routes:app"]
