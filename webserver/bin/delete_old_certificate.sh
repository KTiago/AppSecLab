#!/bin/sh

cd /var/www/html/tmp/ && find ./ -mmin +5 -exec rm -f {} \;

