#!/bin/bash

find $1 -name "*.csv" -print0 | while read -d $'\0' file
do
    awk -i inplace '!seen[$0]++' $file
done
