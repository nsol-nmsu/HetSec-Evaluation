# Bootstrapping test

These experiments measure throughput of the two bootstrapping flows (Coordinator and Agent) defined by Protocols 2 and 3. Each flow is split across three roles per the paper:
- **Agent Provider** — distributes signed app packages
- **Authority** — handles coordinator attestation and returns the attribute mapping store (`M_A`)
- **Coordinator** — handles agent attestation and returns the agent's secret keys (`SK_{A,i}`)

For replicating the paper, run each server on its own TEE machine. For convenience they can be colocated by using different ports.

## Environment

Either application can be run on SGX/gramine using the following commands to build the manifest:

```
gramine-manifest \
  -Dlog_level=error \
  -Darch_libdir=/lib/x86_64-linux-gnu \
  -Dentrypoint=/usr/bin/python3.10 \
  attest_test.manifest.template > attest_test.manifest

gramine-sgx-sign \
  --manifest attest_test.manifest \
  --output attest_test.manifest.sgx
```

For simplicity it can be done without gramine, as the point is to measure throughput. The SGX quote verification enclave must be running:

```
cd Required_Libs/QuoteVerificationSample/SGX/
make SGX_DEBUG=0
./app --tcp 0.0.0.0 7777
```

## File names per platform

The Provider script is named differently across platforms (legacy):
- SGX: `Agent_Provider_throughput.py`
- TDX / SEV-SNP: `Agent_MarketPlace_throughput.py`

The Authority and Coordinator scripts (`Authority_throughput.py`, `Agent_Coor_throughput.py`) are consistent across all platforms.

## Coordinator Bootstrapping Test

Measures the rate at which Coordinator enclaves can be onboarded (Protocol 2). Requires the **Provider** and **Authority** servers; the client emulates a server bootstrapping a coordinator.

Server side (SGX example — run each on a separate machine, or change ports if colocating):
```
cd Agent_Marketplace_test/SGX/
python Agent_Provider_throughput.py    # serves Coordinator_Start
python Authority_throughput.py         # serves Coordinator_Attest_2
```

Client side: edit `clientBootstrap_coor.py` to set `addr_provider` and `addr_authority`, then run:
```
bash run_Coor_BootStrap_test.sh
```

## Agent Bootstrapping Test

Measures the rate at which Agent enclaves can be onboarded (Protocol 3). Requires the **Provider** and **Coordinator** servers; the client emulates a server bootstrapping an agent.

Server side (SGX example):
```
cd Agent_Marketplace_test/SGX/
python Agent_Provider_throughput.py    # serves Agent_Start
python Agent_Coor_throughput.py        # serves Agent_Attest
```

Client side: edit `clientBootstrap_agent.py` to set `ap_addr` (Provider) and `coor_addr` (Coordinator), then run:
```
bash run_Agent_BootStrap_test.sh
```
