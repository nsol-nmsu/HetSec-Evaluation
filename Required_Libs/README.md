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