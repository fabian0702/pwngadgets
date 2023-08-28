import pwn
import re
import binascii
import shlex

class InvalidProcException(Exception):
    "Raised when the input is not a valide pwn.process or a valide pid"
    pass

class ProcNotFoundException(Exception):
    "Raised when the input is not a valide pwn.process or a valide pid"
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
    def flipEndianess(self, value:str):
        return ''.join([value[i:i+2] for i in range(0, len(value), 2)][::-1])
    def findHexValue(self, hexValue, endianess = 'little', previousMatches:list[int]=None) -> list[int]:
        """Searches a hexvalue in the dump and return the indecies found as a list, can use result from previous link to further filter the indecies"""
        if not endianess == self.endianess:
            hexValue = self.flipEndianess(hexValue)
        matches = [i for i, element in enumerate(self.leakElements) if hexValue in element]
        if not previousMatches is None:
            return [i for i in matches if i in previousMatches]
        return matches
    
    def decodeString(self, hexValues:list[str], endianess:str=None, crop=False):
        if endianess is None:
            endianess = self.endianess
        hexStr = ''.join(hexValues).replace('0x', '')
        if crop and len(hexStr) % 2 == 1:
            hexStr = hexStr[:-1]
        decodedString = binascii.unhexlify(hexStr)
        return decodedString[::-1]

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
from pwn inport *
import shlex

def ncatRemote(url:str) -> pwn.remote:
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
    args = shlex.split(url)
    return pwn.remote(host=args[-2], port=int(args[-1]), ssl='--ssl' in url)
    


def getProcMappings(p:pwn.process | int) -> str:
    if type(p) == pwn.process:
        pid = p.proc.pid
    elif type(p) == int and p > 0:
        pid = p
    else:
        raise InvalidProcException('the given argument is neither a valide pwn.process or a valide pid')
    try:
        with open(f'/proc/{pid}/maps') as f:
            content = f.read()
            print(content)
    except (OSError, FileNotFoundError):
        raise ProcNotFoundException('the process specified by the given pid was not found or not accessable.')
    return content