#!/bin/bash

domain=$1
wordlist="/home/bugswami1008/VAPT/SecLists/Discovery/DNS/deepmagic.com-prefixes-top500.txt"
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

probing(){
cat $domain/domains.txt | httpx -threads 200 -o $domain/Recon/httpx.txt
}
probing

scanner(){ 
cat httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/cves/ -c 50 -o $domain/Recon/nuclei/cves.txt
cat httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/technologies/ -c 50 -o $domain/Recon/nuclei/technologies.txt
cat httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/files/ -c 50 -o $domain/Recon/nuclei/files.txt
cat httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/fuzzing/ -c 50 -o $domain/Recon/nuclei/fuzzing.txt
cat httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/generic-detections/ -c 50 -o $domain/Recon/nuclei/generic-detections.txt
cat httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/panels/ -c 50 -o $domain/Recon/nuclei/panels.txt
cat httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/payloads/ -c 50 -o $domain/Recon/nuclei/payloads.txt
cat httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/security-misconfiguration/ -c 50 -o $domain/Recon/nuclei/security-misconfiguration.txt
cat httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/subdomain-takeover/ -c 50 -o $domain/Recon/nuclei/subdomain-takeover.txt
cat httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/tokens/ -c 50 -o $domain/Recon/nuclei/tokens.txt
cat httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/vulnerabilities/ -c 50 -o $domain/Recon/nuclei/vulnerabilities.txt
cat httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/workflows/ -c 50 -o $domain/Recon/nuclei/workflows.txt
}
scanner

wayback_data(){
cat $domain/domains.txt | waybackurls | tee $domain/Recon/wayback/tmp.txt
$domain/Recon/wayback/tmp.txt | egrep -v "\.woff|\.ttf|\.png|\.jpeg|\.jpg|\.css|\.svg|\.ico|\.eot" | sed 's/:80//g;s/:443//g' | sort -u > $domain/Recon/wayback/wayback.txt
}
wayback_data

valid_urls(){ 
ffuf -c -u "FUZZ" -W $domain/Recon/wayback/wayback.txt -of csv -o $domain/Recon/wayback/valid-tmp.txt
cat $domain/Recon/wayback/valid-tmp.txt | grep http | awk -F "," '{print $1}' >> $domain/Recon/wayback/valid.txt
rm $domain/Recon/wayback/valid-tmp.txt 
}
valid_urls

gf_pattern(){
gf xss $domain/Recon/wayback/wayback.txt | tee $domain/Recon/gf/xss.txt
gf sqli $domain/Recon/wayback/wayback.txt | tee $domain/Recon/gf/sqli.txt
}
gf_pattern
