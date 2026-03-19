#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "------------------------------------------------"
echo "  Android Symbolic Execution Tool - Setup       "
echo "------------------------------------------------"

# 1. Update System and Install System Dependencies
echo "[*] Installing system dependencies (requires sudo)..."
sudo apt-get update
sudo apt-get install -y \
    python3-pip \
    python3-dev \
    python3-venv \
    libffi-dev \
    libssl-dev \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev

# 2. Setup Virtual Environment
echo "[*] Setting up Python virtual environment (sym_exec_env)..."
if [ ! -d "sym_exec_env" ]; then
    python3 -m venv sym_exec_env
fi

# Activate virtual environment
source sym_exec_env/activate

# 3. Upgrade Pip
echo "[*] Upgrading pip..."
pip install --upgrade pip

# 4. Install Python Dependencies
echo "[*] Installing Python libraries..."

# Static Analysis and APK Parsing
pip install androguard

# SMT Solver for Symbolic logic
pip install z3-solver

# Binary Analysis for Native code (.so)
pip install angr claripy

# Graph structures for CFG
pip install networkx

echo "------------------------------------------------"
echo "  Setup Complete!                               "
echo "------------------------------------------------"
echo "To start analyzing APKs, run:"
echo "source sym_exec_env/activate"
echo "python3 main.py <path_to_apk>"
echo "------------------------------------------------"
