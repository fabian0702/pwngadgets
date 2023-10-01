import pwn
import re
import binascii
import shlex
import string

class InvalidProcException(Exception):
    "Raised when the input is not a valide pwn.process or a valide pid"
    pass

class ProcNotFoundException(Exception):
    "Raised when the input is not a valide pwn.process or a valide pid"
    pass

class InvalidMemoryExeption(Exception):
    "Raised when the requested Memory region is not mapped"
    pass

class InvalideHexString(Exception):
    "Raised when the hex string is an odd length"
    pass

def interactiveToCommads(process:pwn.process, *argsm, printCommands=True, nonPrintableCharacters=True, **kwargsm):
    t = pwn.tube()

    charactersSending = [b'']
    linesRecv = []
    commands = []

    def send(*args, **kwargs):
        charactersSending.append(args[0])
        if b'\n' in charactersSending:
            line = b''.join(charactersSending)
            if nonPrintableCharacters:
                for x in re.findall(b'\\\\x[0-9a-fA-F].', line):
                    line = line.replace(x, binascii.unhexlify(x[2:]))
                process.send(line)
            line = line.strip(b'\r\n')
            if len(linesRecv) > 0:
                commands.append(f'p.sendlineafter({linesRecv[-1]}, {line})')
            else:
                commands.append(f'p.sendline({line})')
            
            charactersSending.clear()
        process.send(args[0] if not nonPrintableCharacters else b'', *args[1:], **kwargs)
    t.send = send

    def recv(*args, **kwargs):
        data = process.recv(*args, **kwargs)
        if data:
            data += linesRecv.pop() if len(linesRecv) > 0 else b''
            linesRecv.extend(data.splitlines())
        return data
    t.recv = recv

    t.interactive(*argsm, **kwargsm)

    pwn.info('Done, generating commands...')

    if printCommands:
        print('\n'.join(commands))

    return commands

import time, requests, os, json

bergAuthToken = ''

def getAuthToken(forceReauth=False):
    from selenium import webdriver

    env = os.environ.get('bergAuth', None)

    if not env is None and not forceReauth:
        return env
    browser = webdriver.Chrome()
    browser.get('https://library.m0unt41n.ch/api/v1/login')
    while not browser.current_url == 'https://library.m0unt41n.ch/':
        time.sleep(0.1)

    bergAuth = [cookie for cookie in browser.get_cookies() if cookie['name'] == 'berg-auth'][0]
    browser.close()
    os.environ.update({'bergAuth':bergAuth['value']})
    return bergAuth['value']

def getRemoteFromChallengeName(challengeName:str, newBergAuthToken:str=None) -> pwn.remote:
    global bergAuthToken
    if newBergAuthToken is None and bergAuthToken is None:
        bergAuthToken = getAuthToken(forceReauth=False)
    elif not newBergAuthToken is None:
        bergAuthToken = newBergAuthToken

    session = requests.Session()

    while True:
        bergAuthToken = getAuthToken()
        request = requests.get('https://library.m0unt41n.ch/api/v1/self', cookies={'berg-auth':bergAuthToken})
        self = json.loads(request.content)
        session.cookies = request.cookies
        if not self['player'] is None:
            break

    currentChallenge = self['challengeInstance']

    if not currentChallenge['name'] is None and not currentChallenge['name'] == challengeName:
        print(f'terminating challenge instance: {currentChallenge["name"]}')
        session.post('https://library.m0unt41n.ch/api/v1/challengeInstance/stop')
        self = json.loads(session.get('https://library.m0unt41n.ch/api/v1/self').content)
        currentChallenge = self['challengeInstance']

    if currentChallenge['name'] is None:
        session.post('https://library.m0unt41n.ch/api/v1/challengeInstance/start', data={'challenge':challengeName})
        print(f'started challenge instance: {challengeName}')
        self = json.loads(session.get('https://library.m0unt41n.ch/api/v1/self').content)
        currentChallenge = self['challengeInstance']

    ssl = 'chall' in currentChallenge['services']['hostname']

    return pwn.remote(currentChallenge['services']['hostname'], currentChallenge['services']['port'], typ=currentChallenge['services']['protocol'], ssl=ssl)

def getFlagFromInteractive(p:pwn.process, flagRegex=r'shc20\d\d{.*}', submit=False) -> str:
    t = pwn.tube()
    def send(*args, **kwargs):
        p.send(*args, **kwargs)
    t.send = send
    linesRecv = []
    def recv(*args, **kwargs):
        data = p.recv(*args, **kwargs)
        if data:
            data += linesRecv.pop() if len(linesRecv) > 0 else b''
            linesRecv.extend(data.splitlines())
            flags = re.findall(flagRegex.encode(), data)
            if len(flags) > 0:
                submitFlag(flags.pop(), submit)
        return data
    t.recv = recv

    t.interactive()

def exfiltrateFlag(p:pwn.process, flagRegex=r'shc20\d\d{.*}', check:bool=True, submit:bool=False) -> str:
    with open('exfiltrate.sh', 'r') as f:
        commands = f.read()
        p.sendline(commands)
    data = p.recvall()
    flags = re.findall(flagRegex.encode(), data)
    pwn.info(f'Found flags {flags}')
    if not submit:
        return
    for flag in flags:
        submitFlag(flag, check=check)

def submitFlag(flag:str, challengeName:str=None, newBergAuthToken:str=None, submit:bool=True, check:bool=True) -> None:
    if check:
        pwn.info(f"Do you want to submit the flag '{flag}' (y/n)")
        if not 'y' in input(''):
            return
    if not submit and not check:
        pwn.info(f'Flag: {flag}')
        return
    if challengeName is None:
        global bergAuthToken
        if newBergAuthToken is None and bergAuthToken is None:
            bergAuthToken = getAuthToken(forceReauth=False)
        elif not newBergAuthToken is None:
            bergAuthToken = newBergAuthToken
        self = json.loads(requests.get('https://library.m0unt41n.ch/api/v1/self', cookies={'berg-auth':bergAuthToken}))
        challengeName = self['challengeInstance']['name']
    requests.post('https://library.m0unt41n.ch/api/v1/flag', data={"challenge": challengeName,"flag": flag})