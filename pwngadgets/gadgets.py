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

class Leak:
    class LeakSegment:
        name = ''
        path = ''
        startAddress = 0
        endAddress = 0
        readable=False
        writable=False
        executable = False
        def __init__(self, path:str, baseOffset:str, startAddress:str, endAddress:str, permission:str) -> None:
            self.name = path.split('/')[-1].split('.')[0].replace('[', '').replace(']', '')
            self.path = path
            self.permissions = permission
            self.readable = 'r' in permission
            self.executable = 'x' in permission
            self.writable = 'w' in permission
            self.startAddress = int(startAddress,16)
            self.endAddress = int(endAddress, 16)
            self.baseAddress = self.startAddress - int(baseOffset, 16)
            self.addresses:list[int] = []
            self.addressOffsets:list[int] = []
        def __str__(self) -> str:
            return f'Segment: {self.name} starting at {hex(self.startAddress)} - {hex(self.endAddress)} with {self.permissions} permissions with possible indecies {self.addresses}'
    segments:list[LeakSegment] = []
    leakRegex = r'(0x[0-9a-fA-F]+)|\(nil\)'
    endianess = 'big'
    def __init__(self, leak:str, process:pwn.process) -> None:
        self.rawLeak = leak
        with open(f'/proc/{process.proc.pid}/comm') as f:
            self.procname = f.read().strip()
        self.endianess = process.elf.endian
        self.leakElements = re.findall(self.leakRegex, self.rawLeak)
        self.getProcMapping(process)
        for i, element in enumerate(self.leakElements):
            if len(element) == 0:
                continue
            address = int(element, 16)
            for segment in self.segments:
                if segment.startAddress < address and address < segment.endAddress:
                    segment.addresses.append(i)
                    segment.addressOffsets.append(address-segment.baseAddress)
    
    def getProcMapping(self, proc:int|pwn.process) -> list[LeakSegment]:
        """Requests the process map for a process with the given pid and returns them as list of LeakSegments with each segments corresponding to a line in the mappings file"""
        content = getProcMappings(proc) 
        memAreas = [' '.join(line.split()) for line in content.splitlines()]
        for memLine in memAreas:
            if memLine.count(' ') < 5:
                continue
            adress, permissions, baseOffset, _, _, path = memLine.split()
            startAddress, endAddress = adress.split('-')
            self.segments.append(self.LeakSegment(path=path, baseOffset=baseOffset, startAddress=startAddress, endAddress=endAddress, permission=permissions))
        return self.segments
    def getSegment(self, name:str, permissions = 'p', hasToHaveIndexInLeak=False) -> LeakSegment:
        """Searches for a segment with the right name and fitting permissions, return the first match otherwise none"""
        possibleSegments = [seg for seg in self.segments if name in seg.name and any(permission in seg.permissions for permission in permissions)]
        if hasToHaveIndexInLeak:
            possibleSegments = [segment for segment in possibleSegments if len(segment.addresses)]
        if len(possibleSegments):
            return possibleSegments[0]
        return None
    
    def findHexValue(self, hexValue, endianess = 'little', previousMatches:list[int]=None) -> list[int]:
        """Searches a hexvalue in the dump and return the indecies found as a list, can use result from previous link to further filter the indecies"""
        if not endianess == self.endianess:
            hexValue = flipEndianess(hexValue)
        matches = [i for i, element in enumerate(self.leakElements) if hexValue in element]
        if not previousMatches is None:
            return [i for i in matches if i in previousMatches]
        return matches

    def genCode(self):
        procSegment = self.getSegment(self.procname, hasToHaveIndexInLeak=True)
        stackSegment = self.getSegment('stack', hasToHaveIndexInLeak=True)
        heapSegment = self.getSegment('heap', hasToHaveIndexInLeak=True)
        libcSegment = self.getSegment('libc', hasToHaveIndexInLeak=True)
        variableNames = ['funtion' if procSegment is not None else '',
                         'stack' if stackSegment is not None else '',
                         'heap' if heapSegment is not None else '',
                         'libc' if libcSegment is not None else '']
        lookupsWithOffsets = [f'int(leakedSegments[{procSegment.addresses[0]}], 16) - {hex(procSegment.addressOffsets[0])}' if not procSegment is None else '',
                              f'int(leakedSegments[{stackSegment.addresses[0]}], 16) - {hex(stackSegment.addressOffsets[0])}' if not stackSegment is None else '',
                              f'int(leakedSegments[{heapSegment.addresses[0]}], 16) - {hex(heapSegment.addressOffsets[0])}' if not heapSegment is None else '',
                              f'int(leakedSegments[{libcSegment.addresses[0]}], 16) - {hex(libcSegment.addressOffsets[0])}' if not libcSegment is None else '']
        return f'''
leakedSegments = re.findall(r"{self.leakRegex}", leak)
{', '.join(variableNames)} = [{', '.join(lookupsWithOffsets)}]
        '''

def genTemplate(elfName):
    return f'''
from pwn import *
import shlex

def ncatRemote(url:str) -> remote:
    args = shlex.split(url)
    return remote(host=args[-2], port=int(args[-1]), ssl='--ssl' in url)

local = True
elf = ELF('{elfName}')
if local:
    p =elf.process()
else:
    p = ncatRemote('nc localhost 5000')

def p64(val):
    return pack(val, 64)
        '''

def getPayloadOffset(p:pwn.process, payload=b''):
    p.wait()

    core = p.corefile

    payloadLength = pwn.cyclic_find(core.fault_addr)

    adjustedPayload = pwn.fit({
        payloadLength: payload
    })

    return adjustedPayload, payloadLength

def ncatRemote(url:str) -> pwn.remote:
    """Function to convert a ncat command to pwn.remote"""
    args = shlex.split(url)
    return pwn.remote(host=args[-2], port=int(args[-1]), ssl='--ssl' in url)
    
def _validateProc(p):
    """Internal Function to validate a given process argument"""
    if type(p) == pwn.process:
        pid = p.proc.pid
    elif type(p) == int and p > 0:
        pid = p
    else:
        raise InvalidProcException('the given argument is neither a valide pwn.process or a valide pid')
    if not os.path.exists(f'/proc/{pid}'):
        raise InvalidProcException(f"No process found with pid: {pid}")
    return pid

def getProcMappings(p:pwn.process | int, printMap:bool=True) -> str:
    """Function to get the memory map of a process"""
    pid = _validateProc(p)
    try:
        with open(f'/proc/{pid}/maps') as f:
            content = f.read()
            if printMap:
                print(content)
    except (OSError, FileNotFoundError):
        raise ProcNotFoundException('the process specified by the given pid was not found or not accessable.')
    return content

def flipEndianess(value:str|bytes):
    """Function to flip the endianess of a hex string or bytes"""
    if type(value) == str:
        if len(value) % 2 == 1:
            raise InvalideHexString('Hex string is an odd length')
        if not all(c in string.hexdigits for c in value):
            raise InvalideHexString('Hex string contains nonascii values')
        rawHex = value.replace('0x', '')
        rawFlipedHex = ''.join([''.join([rawHex[n:n+8][i:i+2] for i in range(0, 8, 2)][::-1]) for n in range(0, len(rawHex), 8)])
        return '0x' if '0x' in value else '' + rawFlipedHex
    if type(value) == bytes:
        return value[::-1]
    
def readProcessMemory(p:pwn.process | int, startAddress:int, endAddress:int) -> bytes:
    pid = _validateProc(p)
    if startAddress > endAddress:
        raise InvalidMemoryExeption('startAddress has to be smaller than endAddress')
    memMap = getProcMappings(p, printMap=False)
    inMappedArea = False
    for line in memMap.splitlines():  # for each mapped region
        m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([-r])', line)
        if m.group(3) == 'r':  # readable region
            start = int(m.group(1), 16)
            end = int(m.group(2), 16)
            if start < startAddress and end > endAddress:
                inMappedArea = True

    if not inMappedArea:
        raise InvalidMemoryExeption('The requested Memory chunk is not mapped')
    
    with open('/proc/{pid}/mem', 'rb') as f:
        f.seek(startAddress)
        mem = f.read(endAddress-startAddress)
        return mem

def decodeString(hexValues:list[str]|str, endianess:str='little', crop=False):
    """Function to convert a hex string or a list of hex strings to bytes"""
    if type(hexStr) == list[str]:
        hexStr = ''.join(hexValues)
    if not all(c in string.hexdigits for c in hexStr):
        raise InvalideHexString('Hex string contains nonascii values')
    if len(hexStr) % 2 == 1:
        if crop:
            hexStr = hexStr[:-1]
        else:
            raise InvalideHexString('Hex string is an odd length')
    if endianess == 'little':
        hexStr = flipEndianess(hexStr)
    return binascii.unhexlify(hexStr.replace('0x', ''))

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium import *
import time, requests, os, json

def getRemoteFromChallengeName(challengeName:str) -> pwn.remote:
    def getAuthToken(forceReauth=False):
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

    session = requests.Session()

    self = {'player':None}

    while self['player'] is None:
        authToken = getAuthToken()
        request = requests.get('https://library.m0unt41n.ch/api/v1/self', cookies={'berg-auth':authToken})
        self = json.loads(request.content)
        session.cookies = request.cookies

    print(self)
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