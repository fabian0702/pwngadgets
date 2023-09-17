import socket
import ssl
import threading, re

headersToRemove = ['Access-Control-Allow-Origin']
htmlToInject = '<iframe src="https://www.google.com" height="200" width="300" title="Iframe Example"></iframe><iframe src="https://www.google.com" height="200" width="300" title="Iframe Example"></iframe><iframe src="https://www.google.com" height="200" width="300" title="Iframe Example"></iframe><iframe src="https://www.google.com" height="200" width="300" title="Iframe Example"></iframe><iframe src="https://www.google.com" height="200" width="300" title="Iframe Example"></iframe><iframe src="https://www.google.com" height="200" width="300" title="Iframe Example"></iframe><iframe src="https://www.google.com" height="200" width="300" title="Iframe Example"></iframe><iframe src="https://www.google.com" height="200" width="300" title="Iframe Example"></iframe><iframe src="https://www.google.com" height="200" width="300" title="Iframe Example"></iframe><iframe src="https://www.google.com" height="200" width="300" title="Iframe Example"></iframe>'

def handleConnection(client:socket.socket, address:str, remoteHostName:str, localPort:int=8080):
    print(f'Received connection from {address}')

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_SSLv23, ciphers="ADH-AES256-SHA")
    data = b''
    while True:
        dataChunk = b''
        remainingContentLength = 0
        while True:
            recv = client.recv(2048)
            dataChunk += recv
            if b'\r\n\r\n' in dataChunk or not recv:
                break

        if remainingContentLength > 0:
            contentChunk = serverSocket.recv(remainingContentLength)
            remainingContentLength -= len(contentChunk)
            dataChunk += contentChunk
        
        if b'Content-Length' in dataChunk and b'\r\n\r\n' in dataChunk:
            match = re.findall(b'Content-Length:\\s(\\d+)', dataChunk)
            if not match is None:
                offset = len(dataChunk) - dataChunk.index(b'\r\n\r\n') - 4
                contentLength = int(match[0])
                contentChunk = client.recv(max(contentLength - offset,0))
                remainingContentLength = max(contentLength - offset,0) - len(contentChunk)
                dataChunk += contentChunk
        data += dataChunk 
        if not b'chunked' in data or b'0\r\n\r\n' in data:
            break
     
    data = data.replace(b'.localhost:'+str(localPort).encode(), b'.'+remoteHostName.encode())
    data = data.replace(b'localhost:'+str(localPort).encode(), b'www.'+remoteHostName.encode())
    for header in headersToRemove:
        data = re.sub(f'{header}.*'.encode(), b'', data)

    #print(data)

    serverSocket.connect((remoteHostName, 443))
    serverSocket.send(data)

    data = b''
    while True:
        dataChunk = b''
        remainingContentLength = 0
        while True:
            recv = serverSocket.recv(2048)
            dataChunk += recv
            if b'\r\n\r\n' in dataChunk or not recv:
                break

        if remainingContentLength > 0:
            contentChunk = serverSocket.recv(remainingContentLength)
            remainingContentLength -= len(contentChunk)
            dataChunk += contentChunk
        
        if b'Content-Length' in dataChunk and b'\r\n\r\n' in dataChunk:
            match = re.findall(b'Content-Length:\\s(\\d+)', dataChunk)
            if not match is None:
                offset = len(dataChunk) - dataChunk.index(b'\r\n\r\n') - 4
                contentLength = int(match[0])
                contentChunk = serverSocket.recv(max(contentLength - offset,0))
                remainingContentLength = max(contentLength - offset,0) - len(contentChunk)
                dataChunk += contentChunk
        data += dataChunk 
        if not b'chunked' in data or b'0\r\n\r\n' in data:
            break

    data = data.replace(b'www.google.com', b'localhost:'+str(localPort).encode())
    data = data.replace(b'.google.com', b'.localhost:'+str(localPort).encode())

    print(b'<' in data)

    if b'body' in data:
        print('abc')
        data = data.replace(b'</body>', htmlToInject.encode()+b'</body>')

    for header in headersToRemove:
        data = re.sub(f'{header}.*'.encode(), b'', data)
    #print(data)

    client.send(data)

    client.close()

    serverSocket.close()

def proxy(remoteHostName, localPort:int=8080, maxThreads:int=None):
    threads:list[threading.Thread] = []
    with socket.socket() as clientSocket:
        host = socket.gethostbyname('localhost')
        clientSocket.bind((host, localPort))
        clientSocket.listen(2)
        try:
            while True:
                threads = list(filter(threading.Thread.is_alive, threads))
                if not maxThreads is None and maxThreads > len(threads):
                    continue
                client, address = clientSocket.accept()
                t = threading.Thread(target=handleConnection, args=(client, address, remoteHostName, localPort))
                t.start()
                threads.append(t)
        except KeyboardInterrupt:
            for t in threads:
                t.join()

proxy('google.com', 1337)