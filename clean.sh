#!/bin/bash

echo "Delete databases..."
rm Server/storage/selling*
rm Server/storage/transactions*
rm -r Server/classes
rm -r Client/classes
rm -r Library/classes
