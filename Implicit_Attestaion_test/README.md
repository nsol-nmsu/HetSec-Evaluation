# Bootstrapping test

These experiemnts require at least two machines. Either application can be run on SGX or gramine using the following commands to make the enviorment: 

cd Attest_Traditional/SGX/
gramine-manifest \
-Dlog_level=error \
-Darch_libdir=/lib/x86_64-linux-gnu \
-Dentrypoint=/usr/bin/python3.10 \
attest_test.manifest.template > attest_test.manifest

gramine-sgx-sign \
--manifest attest_test.manifest \
--output attest_test.manifest.sgx
 
Each machine has a verification setup

SGX Machines
cd Required_Libs/QuoteVerificationSample/SGX/
make SGX_DEBUG=0
./app --tcp 0.0.0.0 7777

TDX Machines
cd Required_Libs/QuoteVerificationSample/SGX/
make SGX_DEBUG=0
./app --tcp 0.0.0.0 7777

SEV-SNP Machines
cd Required_Libs/QuoteVerificationSample/SGX/
make SGX_DEBUG=0
./app --tcp 0.0.0.0 7777

For replicating the results from the paper use thes machine setups from the paper.

## Server Machine Agent Provider Test
Using TDX as an example

Agent 2
cd Agent_Marketplace_test/TDX/
python serverTCP_Attest_test.py

Agent 1 

cd Attest_Traditional/TDX/
python client_attest_test.py


