#!/bin/bash
# VirusTotal script to add signatures.
# /!\ Warning. Current API Key is limited to 4 requests per minutes.

database="evolix.hsb"
apikey="XXX"
file="$1"
md5=$(md5sum "$file" | cut -d' ' -f1)
sha256=$(sha256sum "$file" | cut -d' ' -f1)
size=$(stat -c %s "$file")
report=$(mktemp virustotal.XXX.tmp)

echo "Scanning file ${file}..."
# Search if not already in Evolix database.
grep -q "$sha256" "$database"
if [[ $? == 0 ]]; then
    echo "This file is a virus and already in Evolix database!"
    exit 1
fi

# Send the file for scanning to VirusTotal.
curl https://www.virustotal.com/vtapi/v2/file/scan -F file="@${file}" -F apikey="${apikey}" -o /dev/null -s
# Wait for scan, about 30s, then get the report, parse it and generate a signature.
sleep 20s
curl https://www.virustotal.com/vtapi/v2/file/report -F resource="${md5}" -F apikey="${apikey}" -o "$report" -s
positives=$(grep -Eo '"positives": [0-9]+' "$report" | grep -Eo '[0-9]+')
link=$(grep -Eo 'https://.*/' "$report")
if [[ "$positives" -ge 2 ]]; then
    echo "Virus detected! (${positives} positives)"
    echo "VirusTotal link: $link"
    echo "Adding signature to Evolix database..."
    echo "${sha256}:${size}:DetectedOnVirusTotal+Evolix" >> $database
else
    echo "No virus detected. Not adding a signature to Evolix database."
fi

# Cleaning
rm "$report"
exit 0
