#!/bin/bash

domain=$1
wordlist="/home/bugswami1008/VAPT/SecLists/Discovery/DNS/deepmagic.com-prefixes-top500.txt"
resolvers="/home/bugswami1008/resolvers.txt"

passive_enum(){

mkdir -p $domain $domain/sources $domain/recon $domain/recon/nuclei $domain/recon/wayback $domain/recon/ffuf $domain/recon/gf

subfinder -d $domain -o $domain/sources/subfinder.txt
assetfinder -subs-only $domain | tee $domain/sources/assetfinder.txt
amass enum -passive -d $domain -o $domain/sources/amass.txt
shuffledns -d $domain -w $wordlist -r $resolvers -o $domain/sources/shuffledns.txt
gsan crtsh $domain -o $domain/sources/crtsh.txt

cat $domain/sources/*.txt > $domain/sources/all.txt
sort $domain/sources/all.txt | uniq -u > $domain/sources/sorted.txt

dnsx -l $domain/sources/sorted.txt -resp -a -aaaa -cname -mx -ns -soa -txt -o $domain/sources/dnsx.txt

}
passive_enum

resolving_dns(){
shuffledns -d $domain -list $domain/sources/sorted.txt -o $domain/domains.txt -r $resolvers
}
resolving_dns

http_probe(){
cat $domain/domains.txt | httpx -threads 200 -o $domain/recon/httpx.txt
}
http_probe

nuclie_scanner(){
cat $domain/recon/httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/cves/ -o $domain/recon/nuclei/cve.txt
cat $domain/recon/httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/dns/ -o $domain/recon/nuclei/dns.txt
cat $domain/recon/httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/fuzzing/ -o $domain/recon/nuclei/fuzzing.txt
cat $domain/recon/httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/default-credentials/ -o $domain/recon/nuclei/default-credentials.txt
cat $domain/recon/httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/subdomain-takeover/ -o $domain/recon/nuclei/subdomain-takeover.txt
cat $domain/recon/httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/payloads/ -o $domain/recon/nuclei/payloads.txt
cat $domain/recon/httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/vulnerabilities/ -o $domain/recon/nuclei/vulnerabilities.txt
cat $domain/recon/httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/tokens/ -o $domain/recon/nuclei/tokens.txt
cat $domain/recon/httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/files/ -o $domain/recon/nuclei/files.txt
cat $domain/recon/httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/generic-detections/ -o $domain/recon/nuclei/generic-detections.txt
cat $domain/recon/httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/panels/ -o $domain/recon/nuclei/panels.txt
cat $domain/recon/httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/security-misconfiguration/ -o $domain/recon/nuclei/security-misconfiguration.txt
cat $domain/recon/httpx.txt | nuclei -t /home/bugswami1008/nuclei-templates/workflows/ -o $domain/recon/nuclei/workflows.txt
}
nuclie_scanner

wayback(){
cat $domain/domains.txt | waybackurls | tee $domain/recon/wayback/wayback_tmp.txt
$domain/recon/wayback/wayback_tmp.txt | egrep -v "\.woff|\.tff|\.svg|\.eot|\.png|\.jpeg|\.jpg|\.css|\.ico" | sort -u >> $domain/recon/wayback/wayback_final.txt
}
wayback

valid_urls(){
ffuf -c -u "FUZZ" -w $domain/recon/wayback/wayback_final.txt -mc 200 -of csv -o $domain/recon/ffuf/ffuf_valid_tmp.txt
cat $domain/recon/ffuf/ffuf_valid_tmp.txt | grep http | awk -F "," '{print $1}' >> $domain/recon/ffuf/ffuf_valid.txt
}
valid_urls

gf_patterns(){
gf xss $domain/recon/ffuf/ffuf_valid.txt | tee $domain/recon/gf/xss.txt 
gf sql $domain/recon/ffuf/ffuf_valid.txt | tee $domain/recon/gf/sql.txt
}
gf_patterns
