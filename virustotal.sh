#!/bin/bash
# VirusTotal script to add signatures.
# /!\ Warning. Standard API Key is limited to 4 requests per minutes.

if [[ -f virustotal.cnf ]]; then
    source virustotal.cnf
else
    echo "You need to set virustotal.cnf file! Exiting..."
    exit 1
fi
file="$1"
md5=$(md5sum "$file" | cut -d' ' -f1)
sha256=$(sha256sum "$file" | cut -d' ' -f1)
size=$(stat -c %s "$file")
report=$(mktemp /tmp/virustotal.XXX.tmp)
header=$(mktemp /tmp/virustotal.XXX.tmp)
# Set to false if you want to keep the virus file.
removeVirus=true

# Cleaning on exit.
trap "rm $report $header" EXIT SIGINT

apiReturn() {

    header=$1
    grep -q "HTTP/1.1 204 No Content" "$header"
    if [[ $? == 0 ]]; then
        echo "API Error! Limitation of 4 requests per minutes reached."
        exit 1
    fi
}

echo "Scanning file ${file}..."
if [[ ! -f "$file" ]]; then
    echo "File not found!"
    exit 1
fi
# Search if not already in Evolix database.
grep -q "$sha256" "$database"
if [[ $? == 0 ]]; then
    echo "This file is a virus and already in Evolix database!"
    exit 1
fi

# Send the file for scanning to VirusTotal.
curl https://www.virustotal.com/vtapi/v2/file/scan -F file="@${file}" \
  -F apikey="${apikey}" -o /dev/null -s -D "$header"
apiReturn "$header"
# Wait for scan, about 30s, then get the report.
# If positive, generate a signature.
sleep 30s
curl https://www.virustotal.com/vtapi/v2/file/report -F resource="${md5}" \
  -F apikey="${apikey}" -o "$report" -s -D "$header"
apiReturn "$header"
positives=$(grep -Eo '"positives": [0-9]+' "$report" | grep -Eo '[0-9]+')
link=$(grep -Eo 'https://.*/' "$report")
if [[ "$positives" -ge 2 ]]; then
    echo "Virus detected! (${positives} positives)"
    echo "VirusTotal link: $link"
    echo "Adding signature to Evolix database..."
    echo "${sha256}:${size}:DetectedOnVirusTotal+Evolix" >> "$database"
    if ($removeVirus); then
        rm "$file"
        echo "Removed the virus."
    fi
else
    echo "No virus detected. Not adding a signature to Evolix database."
fi

exit 0
