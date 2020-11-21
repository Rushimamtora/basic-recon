sudo apt-get update ; sudo apt-get upgrade ; sudo apt-get install golang 
wget "https://github.com/projectdiscovery/shuffledns/releases/download/v1.0.4/shuffledns_1.0.4_linux_amd64.tar.gz" ; tar -xzvf shuffledns_1.0.4_linux_amd64.tar.gz ; sudo mv shuffldns /usr/bin/shuffledns ; shuffledns -h

sudo apt update
sudo apt install snapd
sudo snap install amass

git clone https://github.com/projectdiscovery/httpx.git; cd httpx/cmd/httpx; go build; sudo mv httpx /usr/local/bin/; httpx -version

git clone https://github.com/tomnomnom/assetfinder.git; cd assetfinder ; go build ; sudo mv assetfinder /usr/local/bin; assetfinder -h

git clone https://github.com/tomnomnom/waybackurls.git; cd waybackurls ; go build ; sudo mv waybackurls /usr/local/bin; waybackurls -h

git clone https://github.com/projectdiscovery/subfinder.git ;cd subfinder/v2/cmd/subfinder ;go build ;sudo mv subfinder /usr/local/bin/ ; subfinder -h

git clone https://github.com/projectdiscovery/nuclei.git; cd nuclei/v2/cmd/nuclei/; go build; sudo mv nuclei /usr/local/bin/; nuclei -version

