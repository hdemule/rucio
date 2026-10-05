#!/bin/bash
read -rp "Rucio username: " username
sed -i "s/^account *=.*/account = ${username}/" /opt/rucio/etc/rucio.cfg
