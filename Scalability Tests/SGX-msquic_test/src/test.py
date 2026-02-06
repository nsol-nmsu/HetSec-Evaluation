import subprocess
import os
import copy
import time
import pickle
start_time = time.time()
subprocess.run("./src/MABE-decrypt", capture_output=True, text=True).stdout
end_time = time.time()
print("Time to run MABE: ", end_time - start_time) 
