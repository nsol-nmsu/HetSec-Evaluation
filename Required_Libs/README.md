# Required libraies 

## Traditional Attestion requirments 
The only requriement is the Quote Verifcation sample. 

## Het-Sec Attestion requirments 

These are the requried libraies for the the Het-Sec experiments and should not be included in the tradional benchmarks. First apply the Gramine and MsQuic patches. To pull the same version used in our experiments: 

### Gramine
````
git clone https://github.com/gramineproject/gramine.git
cd gramine
git checkout f8eda808155b67f1980df36b45c3f7750db396bf
git apply gramine-MABE.patch
````

### MsQuic
````
git clone https://github.com/microsoft/msquic.git
cd gramine
git checkout a9814940f0a0b2c6a18744cc91c0b5bf2448e82d
git apply msquic-MABE.patch
````

Then build the MSquicWrapper

### MABE library (libmabe.so)

The Python test scripts call MABE through an in-process C library (`libmabe.so`) loaded via `ctypes` instead of spawning the `MABE-encrypt` / `MABE-decrypt` binaries. Each test directory that uses MABE ships with `mabe_api.cpp`, `mabe_api.h`, `MABE.hpp`, and `MABE-util.hpp`; you build `libmabe.so` once per directory.

#### System requirements

- `g++` with C++17 support
- [PBC library](https://crypto.stanford.edu/pbc/) (provides `libpbc`, headers in `/usr/local/include/pbc`)
- [GMP](https://gmplib.org/) (`libgmp`)
- [nlohmann/json](https://github.com/nlohmann/json) single-header (`json.hpp`) on the include path

On Debian/Ubuntu:
````
sudo apt install build-essential libgmp-dev nlohmann-json3-dev
# PBC is not packaged on most distros; build from source:
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar xf pbc-0.5.14.tar.gz && cd pbc-0.5.14
./configure && make && sudo make install
sudo ldconfig
````

#### Build command

Run this from each directory that contains `mabe_api.cpp` (see the list below):
````
g++ -O2 -fPIC -shared mabe_api.cpp -o libmabe.so \
  -I/usr/local/include/pbc -lpbc -lgmp
````

#### Directories that need libmabe.so

- `Implicit_Attestaion_test/Attest_SACM/` (used by `src/`)
- `Implicit_Attestaion_test/Attest_SACM/src/`
- `Implicit_Attestaion_test/Attest_Traditional/TDX/`
- `Scalability Tests/SGX-gramine/src/`
- `Scalability Tests/VM-Based/src/`
- `TaskCompletion_test/saga/experiments/`

Note: `TaskCompletion_test/saga/.gitignore` excludes `*.so`, so `libmabe.so` is intentionally not committed under that tree — build it locally with the command above.
