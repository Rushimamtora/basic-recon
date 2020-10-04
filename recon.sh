#!/bin/bash

domain=$1
wordlist="/home/bugswami1008/VAPT/SecLists/Discovery/DNS/dns-Jhaddix.txt"
resolvers="/home/bugswami1008/resolvers.txt" 

domain_enum(){

mkdir -p $domain $domain/sources $domain/Recon $domain/Recon/nuclei $domain/Recon/wayback

subfinder -d $domain -o $domain/sources/subfinder.txt
assetfinder -subs-only $domain | tee $domain/sources/$domain.com
amass enum -passive -d $domain -o $domain/sources/passive.txt
shuffledns -d $domain -w $wordlist -r $resolvers -o $domain/sources/shuffledns.txt

cat $domain/sources/*.txt > $domain/sources/all.txt
}
domain_enum

resolving_domains(){
shuffledns -d $domain -list $domain/sources/all.txt -o $domain/domains.txt -r $resolvers
}
resolving_domains

http_probe(){
cat $domain/domains.txt | httpx -threads 200 -o $domain/Recon/httpx.txt
}
http_probe

scnner(){ 
cat httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/cves/ -c 50 -o $domain/Recon/nulclei/cves.txt
cat httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/technologies/ -c 50 -o $domain/Recon/nulclei/technologies.txt
cat httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/files/ -c 50 -o $domain/Recon/files/cves.txt
}
scanner

wayback_data(){
cat $domain/domains.txt | waybackurls | tee $domain/Recon/wayback/tmp.txt
$domain/Recon/wayback/tmp.txt | egrep -v "\.woff|\.ttf|\.png|\.jpeg|\.jpg|\.css|\.svg|\.ico|\.eot" | sed 's/:80//g;s/:443//g' | sort -u > domain/Recon/wayback/valid.txt>
}

valid_urls(){ 
fuzzer -c -u "FUZZ" -W $domain/Recon/wayback/wayback.txt -of csv -o $domain/Recon/wayback/valid-tmp.txt
}
valid_urls
