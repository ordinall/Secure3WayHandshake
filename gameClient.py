from scapy.all import *
import time
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP

random_generator = Random.new().read
private_key = RSA.generate(1024, random_generator)
public_key = private_key.publickey()

decryptor = PKCS1_OAEP.new(private_key)


conf.verb = 0

class TcpHandshake(object):

    def __init__(self, target):
        self.seq = 0
        self.seq_next = 0
        self.target = target
        self.dst = target[0]
        self.dport = target[1]
        self.sport = 1234
        self.l4 = IP(dst=target[0])/TCP(sport=self.sport, dport=self.dport, flags=0, seq=random.randrange(0,2**32))
        self.src = self.l4.src

    def start(self):
        return self.send_syn()

    def match_packet(self, pkt):
        if pkt.haslayer(IP) and pkt[IP].dst == self.l4[IP].src and pkt.haslayer(TCP) and pkt[TCP].dport == self.sport and pkt[TCP].ack == self.seq_next:
           return True
        return False

    def _sr1(self, pkt):
        send(pkt)
        ans = sniff(filter="tcp port %s"%self.target[1],lfilter=self.match_packet,count=1,timeout=1)
        return ans[0] if ans else None

    def handle_recv(self, pkt):
        if pkt and pkt.haslayer(IP) and pkt.haslayer(TCP):
            if pkt[TCP].flags & 0x3f == 0x12:   # SYN+ACK
                return self.send_synack_ack(pkt)
        print("Could not do the handshake")
        exit()
        
        return None

    def send_syn(self):
        self.l4[TCP].flags = "S"
        self.seq_next = self.l4[TCP].seq + 1
        response = self._sr1(self.l4)
        self.l4[TCP].seq += 1
        return self.handle_recv(response)

    def send_synack_ack(self, pkt):
        self.l4[TCP].ack = pkt[TCP].seq+1
        self.l4[TCP].flags = "A"
        self.seq_next = self.l4[TCP].seq
        response = self._sr1(self.l4)
        print("Connection Established")

    def recvdata(self):
        pkt = sniff(filter="tcp port %s"%self.target[1],count=1)
        return bytes(pkt[0][TCP].payload)
    
    def senddata(self, data):
        time.sleep(1)
        pkt = IP(dst=self.target[0])/TCP(sport=self.sport, dport=self.dport, flags="PA", seq=random.randrange(0,2**32))
        send(pkt/data)
        
        
    def sendDataEnc(self, data):
        encrypted_data = encryptor.encrypt(data.encode())
        self.senddata(encrypted_data)
    
    def recvDataDec(self):
        enc_data = self.recvdata()
        return decryptor.decrypt(enc_data).decode('utf-8')


theBoard = {'7': ' ' , '8': ' ' , '9': ' ' ,
            '4': ' ' , '5': ' ' , '6': ' ' ,
            '1': ' ' , '2': ' ' , '3': ' ' }
            
def printBoard(board = theBoard):
    print()
    print(board['7'] + '|' + board['8'] + '|' + board['9'])
    print('-+-+-')
    print(board['4'] + '|' + board['5'] + '|' + board['6'])
    print('-+-+-')
    print(board['1'] + '|' + board['2'] + '|' + board['3'])

if __name__=='__main__':
    ip = input("Enter ip of the server: ")
    port = 1234
    conn = TcpHandshake((ip, port))
    conn.start()
    print("Server Public Key: ")
    svpk = conn.recvdata().decode('utf-8')
    print(svpk)
    print("\nClient Private Key: ")
    print(private_key.exportKey().decode('utf-8'))
    
    server_public_key = RSA.importKey(svpk)
    conn.senddata(public_key.exportKey())
    global encryptor
    encryptor = PKCS1_OAEP.new(server_public_key)

    symbolOption = conn.recvDataDec()
    print("\nYour symbol is " + symbolOption)
    turn = 'O'
    serverfirst = True
    while True:
        printBoard()
        inp = ''
        if turn == symbolOption:
            serverfirst = False
            turn = 'X' if symbolOption == 'O' else 'O'
            inp = input("Its your turn, input a number: ")
            while True:
                try:
                    if int(inp) < 1 or int(inp) > 9:
                        inp = input("You entered an incorrect number, Try again: ")
                        continue
                    if theBoard[inp] != ' ':
                        inp = input("That place is already filled with " + theBoard[inp] + " Try putting your symbol somewhere else: ")
                        continue
                    theBoard[inp] = symbolOption
                    break
                except:
                    inp = input("Please Enter a Number: ")
                    continue
            printBoard()
        print("Waiting for the server...")
        if serverfirst:
            otherplayercoord = conn.recvDataDec()
        else:
            otherplayercoord = conn.sendDataEnc(inp)
            otherplayercoord = conn.recvDataDec()
        if (otherplayercoord[0] < '1' or otherplayercoord[0] > '9'):
            if otherplayercoord == symbolOption:
                print("\nYou won !!")
            elif otherplayercoord[0] == '-':
                if otherplayercoord[1] == symbolOption:
                    print("\nTied!")
                else:
                    theBoard[otherplayercoord[1]] = turn
                    printBoard()
                    print("\nTied!")
                
            else:
                theBoard[otherplayercoord[1]] = turn
                printBoard()
                print("\nYou lost !")
            print("Connection Closed!")
            exit()
            
            
        theBoard[otherplayercoord] = turn
        turn = symbolOption