# Bootstrapping test

These experiemnts require at least two machines. Either application can be run on SGX or gramine using the following commands to make the enviorment: 
server-side commands

````
gramine-manifest \
-Dlog_level=error \
-Darch_libdir=/lib/x86_64-linux-gnu \
-Dentrypoint=/usr/bin/python3.10 \
attest_test.manifest.template > attest_test.manifest

gramine-sgx-sign \
--manifest attest_test.manifest \
--output attest_test.manifest.sgx
````

For simplicity it can be done without gramine as the point is to test the thoughout. Though the SGX verification enclave must be run using these commands from the root directory: 

````
cd Required_Libs/QuoteVerificationSample/SGX/
make SGX_DEBUG=0
./app --tcp 0.0.0.0 7777
````
For replicating the results from the paper use a SGX machine for the Agent Provider and Coordinator (Server Version)

## Server Machine Agent Provider Test
Using SGX as an example

server-side
````
cd Agent_Marketplace_test/SGX/
python Agent_Provider_throughput.py
````
client-side commands
````
bash run_Coor_BootStrap_test
````
## Server MachineCoordinator Test
We colocate the Coordinator and agent provider for simplicity, though they can be seperated by Using SGX as an example.

server-side
````
cd Agent_Marketplace_test/SGX/
python Agent_Coor_throughput.py
````
client-side commands
````
bash run_Agent_BootStrap_test
````