# Bootstrapping test

These experiemnts require at least two machines. Either application can be run on SGX or gramine using the following commands to make the enviorment: 
````
cd Attest_Traditional/SGX/

gramine-manifest \
-Dlog_level=error \
-Darch_libdir=/lib/x86_64-linux-gnu \
-Dentrypoint=/usr/bin/python3.10 \
pytorch.manifest.template > pytorch.manifest

gramine-sgx-sign \
--manifest pytorch.manifest \
--output pytorch.manifest.sgx
 ````

For replicating the results from the paper use A SGX machine for Agent 3, a SEV-SNP machine for Agent 2, TDX machine for Agent 1, and a edge machine for the Client. Each should be deployed in the order specified, Agent 3, Agent 2, Agent 1, and finally client. 

## Server Machine Agent Provider Test

### Client
````
cd VM-Based/TDX/src
python clientTLS_test.py # For the RA-TLS test
python clientMSQuic_test # For the HetSec Test
````
### Agent 1
````
cd VM-Based/TDX/src
python async_fed_serverTLS_1.py # For the sequential RA-TLS test
python async_fed_serverTLS_1_parallel.py # For the parallel RA-TLS test
python async_fed_serverMSquic_1.py # For the sequential HetSec Test
python async_fed_serverMSquic_parallel_1.py # For the parallel HetSec Test
````
### Agent 2 
````
cd VM-Based/TDX/src
python async_fed_serverTLS_2.py # For the RA-TLS test
python async_fed_serverMSquic_2.py # For the HetSec Test
````
### Agent 3 
````
cd SGX-gramine/TDX/
gramine-sgx ./pytorch src/async_fed_serverTLS_3.py # For the RA-TLS test
gramine-sgx ./pytorch src/async_fed_serverMSquic_3.py # For the HetSec Test
````