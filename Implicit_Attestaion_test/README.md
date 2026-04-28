# Bootstrapping test

## Requiremnts
For the MABE experiments first build `libmabe.so` in each directory that contains a `mabe_api.cpp`. For this test set that means both `Attest_SACM/` and `Attest_Traditional/TDX/`:
````
g++ -O2 -fPIC -shared mabe_api.cpp -o libmabe.so \
  -I/usr/local/include/pbc -lpbc -lgmp
````

System requirements (PBC, GMP, nlohmann/json) and install commands are documented in `Required_Libs/README.md`.

Ensure all requried libraries are built. 

## Running the tests
These experiemnts require at least two machines. Either application can be run on SGX or gramine using the following commands to make the enviorment: 
````
cd Attest_Traditional/SGX/

gramine-manifest \
-Dlog_level=error \
-Darch_libdir=/lib/x86_64-linux-gnu \
-Dentrypoint=/usr/bin/python3.10 \
attest_test.manifest.template > attest_test.manifest

gramine-sgx-sign \
--manifest attest_test.manifest \
--output attest_test.manifest.sgx
 ````
## Verifcation enlcaves per machine

### SGX Machines
````
cd Required_Libs/QuoteVerificationSample/SGX/
make SGX_DEBUG=0
./app --tcp 0.0.0.0 7777
````
### TDX Machines
````
cd Required_Libs/QuoteVerificationSample/SGX/
make SGX_DEBUG=0
./app --tcp 0.0.0.0 7777
````
### SEV-SNP Machines
````
cd Required_Libs/QuoteVerificationSample/SGX/
make SGX_DEBUG=0
./app --tcp 0.0.0.0 7777
````
For replicating the results from the paper use the machine combinations from the paper.

## Traditonal Server Machine Agent to Agent Test
Using TDX as an example

Agent 2
````
cd Attest_Traditional/TDX/
python serverTCP_Attest_test.py
````
Agent 1 
````
cd Attest_Traditional/TDX/
python client_attest_test.py
````

## SACM Server Machine Agent to Agent Test

Agent 2
````
cd Attest_SACM/
python src/serverTCP_Attest_test.py
````
Agent 1 
````
cd Attest_SACM/
python src/client_attest_test.py
````

