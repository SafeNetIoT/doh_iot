#!/bin/bash 

# Little helper used to compare the number of lines in the outputed CSV files 
#
# Usage: ./check_csv ring_chime_pro
# Expected output: the number of CSV line is equal to the number of *non empty* files in data/dns_only>

DEVICE="$1"

echo "Expected number of lines:"
find data/replayed/"$DEVICE"/* -type f ! -size 0|wc -l
echo "Effective number of lines:"
wc -l data/csv/*"$DEVICE"*
