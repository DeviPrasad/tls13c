#!/bin/bash

# initialize a virtual env in your working directory.
python3 -m venv .
source ./bin/activate

# install the module that you need.
pip3 install pycryptodome

# run the script!
python3 aes_ctr_prp.py
