#!/bin/bash

if [ -f .env ]; then
    source .env
fi

if [ "$USERNAME" = "" ]; then
    echo "USERNAME=$(id -u $USER -n)" >> .env
fi

if [ "$USERID" = "" ]; then
    echo "USERID=$(id -u $USER)" >> .env
fi

if [ "$USERGROUPID" = "" ]; then
    echo "USERGROUPID=$(id -g $USER)" >> .env
fi


