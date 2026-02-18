# Bootstrapping test

These experiemnts require at least two machines. Either application can be run on SGX or gramine using the following commands to make the enviorment: 

For replicating the results from the paper use a machine in the cloud for the reciving agent and a edge machine for the initator. make sure the recieving agent is deployed first. 

## Server Machine Agent Provider Test

reciving agent: First follow the instructions from the SAGA repo to deploy the database, CA auth, and the provider. 
There are tests for the expense_report, create_blogpost, and schedule_meeting agents, The following ecample uses the schedule_meeting agent, the others follow the same procedure. 

### Listener
````
cd saga/experiments
python schedule_meeting.py  listen ../user_configs/emma.yaml # For the SAGA Test
python schedule_meeting_MABE.py  listen ../user_configs/emma.yaml # For the HetSec Test
````
### Initator
````
cd saga/experiments
python schedule_meeting.py  query ../user_configs/bob.yaml ../user_configs/emma.yaml # For the SAGA Test
python schedule_meeting_MABE.py  query ../user_configs/bob.yaml ../user_configs/emma.yaml # For the SAGA Test
````