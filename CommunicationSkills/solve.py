#!/usr/bin/python3
from pwn import *
import re

p = process(["python", "CommunicationSkills.py", "flag.txt", "-m"])

rexp = re.compile(r'((0x)*[a-f0-9]+ [^ a-z0-9]+ (0x)*[a-f0-9]+)'.encode(), re.IGNORECASE)
solved = 0
fin = False
while solved < 1000:
    if not p.can_read():
        continue
    prompt = p.read()
    match = re.search(rexp, prompt)
    if match is None:
        continue
    problem = match.groups()[0].decode()
    answer = round(eval(problem), 2)
    log = f"{problem} = {answer}"
    print(log)
    response = str(answer).encode()
    p.send_raw(response + b'\n')
    solved += 1

while True:
    if not p.can_read():
        continue
    prompt = p.read()
    if prompt.find(b'flag') != -1:
        break

flag = prompt
flag = flag.strip()
flag = flag.decode()
print(flag)

