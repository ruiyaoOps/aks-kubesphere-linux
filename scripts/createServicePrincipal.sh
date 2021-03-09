#!/bin/bash

export SPName=$1

echo "Service Principal creating......"

az ad sp create-for-rbac --name $SPName

echo "Service Principal created"