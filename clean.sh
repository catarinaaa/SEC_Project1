#!/bin/bash

echo "Delete databases..."
rm Server/storage/selling.txt
rm Server/storage/transactions.txt
rm -r Server/classes
rm -r Client/classes
rm -r Library/classes