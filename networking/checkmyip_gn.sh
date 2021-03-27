#!/bin/bash
# Enrich all IPs you are connecting to against GN
# based on @Andrew___Morris idea
# 

sudo netstat -anp TCP | grep ESTAB | grep -v "127.0.0.1" | grep -E -o "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | grep -v "192\.168\.|172\.16\.|172\.17\.|172\.18\.|172\.19\.|172\.20\.|172\.21\.|172\.22\.|172\.23\.|172\.24\.|172\.25\.|172\.26\.|172\.27\.|172\.28\.|172\.29\.|172\.30\.|172\.31\.|10\." | sort -u | while read ip; do curl "https://api.greynoise.io/v3/community/"$ip; echo; done
