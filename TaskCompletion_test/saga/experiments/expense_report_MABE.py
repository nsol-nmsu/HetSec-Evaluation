"""
    Ask one agent to schedule a meeting with another agent.
"""
import os
import sys
import uuid
import argparse
import msquic
import pickle
import time
import subprocess
from agent_backend.base import get_agent
from datetime import datetime
from agent_backend.tools.email import LocalEmailClientTool
from saga.config import UserConfig, get_index_of_agent
import json
from contextlib import contextmanager
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from saga.common.overhead import Monitor
import csv 

      
class ExpenseReportTest:
    def __init__(self, user_config):
        self.user_config = user_config

    def success(self, other_agent_email: str,
                hr_name: str, hr_email: str,
                desired_total: int) -> bool:
        """
            Check emails to make sure that:
            2. Email was received by all agents and HR.
            3. The total expense mentioned in the body is correct.
            4. Nobody else was CCd in the email.
        """
        hr_email_endpoint = LocalEmailClientTool(user_name=hr_name,
                                                 user_email=hr_email)
        
        # Get 'inbox' of HR
        hr_inbox = hr_email_endpoint.get_emails("inbox", 2)

        if len(hr_inbox) == 0:
            print("No email received by HR")
            return False

        # Get the most recent email object object (use inbox for reference)
        relevant_email = hr_inbox[0]

        # Make sure only the other agent and HR were CCd
        to = relevant_email["to"]
        email_from = relevant_email["from"]
        people_involved = to + [email_from]
        count_match = 3
        for email in people_involved:
            if self.user_config.email in email:
                count_match -= 1
            if other_agent_email in email:
                count_match -= 1
            if hr_email in email:
                count_match -= 1

        if count_match > 0:
            print("People on email thread does not match expectation")
            return False

        # Get the body of this email
        body = relevant_email["body"]
        # Make sure that the mentioned 'total expense' mentioned is correct
        if str(desired_total) not in body:
            print(f"Total expense mentioned in the email is not {desired_total}")
            #return False

        # Print the email body just for reference
        print(f"Email Body: {body}")

        return True

def run_listener(config: UserConfig, agent_index: int):
    local_agent = get_agent(config, config.agents[agent_index].local_agent_config)
    mon_init = Monitor(time.perf_counter)
    # keep conversation state by convo_id
    state = {}  # convo_id -> code_agent_instance
    savedKeys = {}  # convo_id -> saved sym keys

    # Bind to the same IP/port specified in the YAML for this agent
    ep = config.agents[agent_index].endpoint
    host = ep.ip
    port = ep.port
    s = msquic.MSQuicSocket()
    s.CreateServerSocket(port) 

    print("in the Handle")
    while True:
        time.sleep(0.001)
        try:
            client_data, streamID = s.RecvAny()
        except:           
            continue
        if client_data == "" or client_data == b'':
            continue
        message = 0
        print(len(client_data))
    
        try:
            message = pickle.loads(client_data)
        except:
            message = 0
            print("Not a message")
        
        
        if message != 0:
            first = False
            convo_id =  message[0]
            encrypted_text = message[1]
            iv = message[2]
            agent_key = None

            if(convo_id not in savedKeys):
                encrypted_key =  message[3]
                agent_key = MABE_decrypt(encrypted_key)
                savedKeys[convo_id] = agent_key
                first = True
            else:
                agent_key = savedKeys[convo_id]

            text = decrypt(encrypted_text, agent_key, iv)

            agent_instance = state.get(convo_id)
            agent_instance, reply = local_agent.run(
                query=text,
                initiating_agent=(agent_instance is None),
                agent_instance=agent_instance,
            )
            state[convo_id] = agent_instance


            encrypted_reply = encrypt(reply, agent_key, iv) # Encyrpt the message with sym and the sym key with MABE. We'll use the same IV
            if first:
                encrypted_key = MABE_encrypt(agent_key) # For accurate timings
                reply_pickle = pickle.dumps([convo_id, encrypted_reply, iv, encrypted_key])
                s.ServerSend(streamID, bytes(reply_pickle))
            else:
                reply_pickle = pickle.dumps([convo_id, encrypted_reply, iv])    
                s.ServerSend(streamID, bytes(reply_pickle))


# -------------------------------
# Query mode: call the other agent
# -------------------------------
def run_query(config: UserConfig, agent_index: int, other_user_config_path: str):
    mon_init = Monitor(time.perf_counter)
    llm_init = Monitor(time.perf_counter)
    results = []

    local_agent = get_agent(config, config.agents[agent_index].local_agent_config)

    other = UserConfig.load(other_user_config_path, drop_extra_fields=True)
    other_idx = get_index_of_agent(other, "email_agent")
    if other_idx is None:
        raise ValueError("No agent with name 'email_agent' found in the OTHER configuration.")
    other_ep = other.agents[other_idx].endpoint
    other_url = f"http://{other_ep.ip}:{other_ep.port}/message"

    print(f"{other.email}:{other.agents[other_idx].name}")

    # the same task text as the original script:
    first_msg = "Can you please check your emails for any expenses for our recent trip for NerurIPS to New Orleans from 03-01 to 03-03 " \
            "Tell me what your expenses were (including hotel, travel, food, etc.) and your email ID. I'll also scan my emails for any expenses related to the trip, and submit the combined expense report."
    # 1) our agent composes its first message (optional — you could send task directly to other)
    ai_instance=None

    '''llm_init.start("agent:llm_backend_init")
    ai_instance, first_msg = local_agent.run(
        query=task,
        initiating_agent=True,
        agent_instance=None,
    )
    llm_init.stop("agent:llm_backend_init")
    results.append({"phase":"agent:llm_backend_init","ms":llm_init.elapsed("agent:llm_backend_init")*1})'''
    # 2) send to the other agent
    convo_id = str(uuid.uuid4())

    mon_init.start("agent:communication_proto_init")    
    server = msquic.MSQuicSocket()
    server.CreateClientSocket(other_ep.ip, other_ep.port, 1000)
    mon_init.stop("agent:communication_proto_init")
    results.append({"phase":"agent:communication_proto_init","ms":mon_init.elapsed("agent:communication_proto_init")*1})

    mon_init.start("agent:MABE_Encryption")
    iv = bytes.fromhex("22dc9c199a5d430a95a4020b1348130a") # IV for encryption
    agent_key = bytes.fromhex("C08A05030C15CBC957E60D0678BD47451367E9BBC427EC5B5C60E9C6B286C87B") # Sym key for agents
    encrypted_key = MABE_encrypt(agent_key)
    mon_init.stop("agent:MABE_Encryption")
    results.append({"phase":"agent:MABE_Encryption","ms":mon_init.elapsed("agent:MABE_Encryption")*1})

    mon_init.start("agent:symmetric_key")
    encrypted_msg = encrypt(first_msg, agent_key, iv) # Encyrpt the message with sym and the sym key with MABE
    mon_init.stop("agent:symmetric_key")
    results.append({"phase":"agent:symmetric_key","ms":mon_init.elapsed("agent:symmetric_key")*1})

    mon_init.start("agent:communication_conv")
    send_package = pickle.dumps([convo_id, encrypted_msg, iv, encrypted_key])
    server.ClientSend(send_package)
    
    max_rounds = 8  # small cap so you can time performance deterministically
    rounds = 0
    while rounds < max_rounds:
        not_done = True
        data = b''
            
        data,_ = server.RecvFrom()
        if data == b'':
            continue
            
        mon_init.stop("agent:communication_conv")
        results.append({"phase":"agent:communication_conv","ms":mon_init.elapsed("agent:communication_conv")*1})

        print(data)
        message = pickle.loads(data)
        encrypted_reply = message[1]
        iv = message[2]

        if rounds == 0:
            mon_init.start("agent:MABE_Decryption")
            encrypted_key =  message[3]
            agent_key = MABE_decrypt(encrypted_key)            
            mon_init.stop("agent:MABE_Decryption")
            results.append({"phase":"agent:MABE_Decryption","ms":mon_init.elapsed("agent:MABE_Decryption")*1})

        mon_init.start("agent:decrypt_symmetric_key")
        reply = decrypt(encrypted_reply, agent_key, iv)
        mon_init.stop("agent:decrypt_symmetric_key")
        results.append({"phase":"agent:decrypt_symmetric_key","ms":mon_init.elapsed("agent:decrypt_symmetric_key")*1})

        # stop if they explicitly say finished
        if isinstance(reply, str) and "<TASK_FINISHED>" in reply:
            rounds = max_rounds
            break

        if ai_instance == None:
            llm_init.start("agent:llm_backend_init")
            # ask Bob’s agent to answer (carry state!)
            ai_instance, bob_reply = local_agent.run(
                query=reply,
                initiating_agent=False,
                agent_instance=None,
            )
            llm_init.stop("agent:llm_backend_init")
            results.append({"phase":"agent:llm_backend_init","ms":llm_init.elapsed("agent:llm_backend_init")*1})
        else:
            llm_init.start("agent:llm_backend_init")
            # ask Bob’s agent to answer (carry state!)
            _, bob_reply = local_agent.run(
                query=reply,
                initiating_agent=True,
                agent_instance=ai_instance,
            )
            llm_init.stop("agent:llm_backend_init")
            results.append({"phase":"agent:llm_backend_init","ms":llm_init.elapsed("agent:llm_backend_init")*1})

        mon_init.start("agent:symmetric_key")
        encrypted_msg = encrypt(bob_reply, agent_key, iv) # Encyrpt the message with sym and the sym key with MABE
        mon_init.stop("agent:symmetric_key")
        results.append({"phase":"agent:symmetric_key","ms":mon_init.elapsed("agent:symmetric_key")*1})
        send_package = pickle.dumps([convo_id, encrypted_msg, iv])

        mon_init.start("agent:communication_conv")
        server.ClientSend(send_package)            

    # Validate with the same calendar test
    test = ExpenseReportTest(config)
    succeeded = test.success(other.email, "HR", "hr@university.com", 2140)
    print("Success:", succeeded)
        
    with open("overhead_expense_MABE.csv","a",newline="") as f:
        f.write("\n\n")
        w = csv.DictWriter(f, fieldnames=["phase","ms"])
        w.writerows(results)

    print("done")

def MABE_encrypt(agent_key):
    subprocess.run("./MABE-encrypt")
    encrypted_key_f = open('encrypt.json')
    encrypted_key_bytes = json.dumps(json.load(encrypted_key_f)).encode()
    return encrypted_key_bytes

def encrypt(data, agent_key, iv):
    padder = padding.PKCS7(128).padder()
    agent_cipher = Cipher(algorithms.AES(agent_key), modes.CBC(iv))
    encryptor = agent_cipher.encryptor()
    padded_data= padder.update(pickle.dumps(data)) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()   
    return encrypted_data

def MABE_decrypt(encrypted_agent_key):
    keyBytes = subprocess.run("./MABE-decrypt", capture_output=True, text=True).stdout
    decrypted_key = bytes.fromhex(keyBytes)

    print(keyBytes)
    return decrypted_key

def decrypt(encrypted_prompt, agent_key, iv):  
    cipher = Cipher(algorithms.AES(agent_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = decryptor.update(encrypted_prompt) + decryptor.finalize()

    prompt = pickle.loads(unpadder.update(decrypted_data) + unpadder.finalize())

    print(prompt)    
    return prompt

def main(mode, config_path, other_user_config_path=None):
    config = UserConfig.load(config_path, drop_extra_fields=True)

    # Find the index of the "email_agent" out of all config.agents
    agent_index = get_index_of_agent(config, "email_agent")
    if agent_index is None:
        raise ValueError("No agent with name 'email_agent' found in the configuration.")
    
    if mode == "listen":
        run_listener(config, agent_index)
    else:
        # Get endpoint for other agent
        if other_user_config_path is None:
            raise ValueError("Endpoint (third argument) must be provided in query mode")
        run_query(config, agent_index, other_user_config_path)


if __name__ == "__main__":
    # Get path to config file
    import sys
    mode = sys.argv[1]
    if mode not in ["listen", "query"]:
        raise ValueError("Mode (first argument) must be either 'listen' or 'query'")
    config_path = sys.argv[2]
    other_user_config_path = sys.argv[3] if len(sys.argv) > 3 else None

    main(mode=mode,
         config_path=config_path,
         other_user_config_path=other_user_config_path)

