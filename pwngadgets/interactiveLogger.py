import pwn, pwngadgets, re, binascii
from pwnlib import term

def interactiveNonprintable(process:pwn.process, *argsm, spawnInteractive=True,**kwargsm):
    t = pwn.tube()
    remainingCharacters = []
    def send(*args, **kwargs):
        remainingCharacters.append(args[0])
        if b'\n' in remainingCharacters:
            data = b''.join(remainingCharacters)
            for x in re.findall(b'\\\\x[0-9a-fA-F].', data):
                data = data.replace(x, binascii.unhexlify(x[2:]))
            process.send(data, *args[1:], **kwargs)
            remainingCharacters.clear()
        else:            
            process.send(b'', *args[1:], **kwargs)
    t.send = send
    
    def recv(*args, **kwargs):
        return process.recv(*args, **kwargs)
    t.recv = recv

    if not spawnInteractive:
        return t
    t.interactive(*argsm, **kwargsm)

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