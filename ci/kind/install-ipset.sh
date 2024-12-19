#!/usr/bin/env bash

if ! command -v ipset >/dev/null 2>&1; then
    echo "ipset not found. Installing..."
    if command -v apt >/dev/null 2>&1; then
        sudo apt update && sudo apt install -y ipset
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y ipset
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y ipset
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --noconfirm ipset
    elif command -v zypper >/dev/null 2>&1; then
        sudo zypper install -y ipset
    else
        echo "Package manager not supported. Please install ipset manually."
        exit 1
    fi
else
    echo "ipset is already installed."
fi

