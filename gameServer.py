from scapy.all import *
import time
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
import random

random_generator = Random.new().read
private_key = RSA.generate(1024, random_generator)
public_key = private_key.publickey()

decryptor = PKCS1_OAEP.new(private_key)

conf.verb = 0

class TcpHandshakeServer(object):

    def __init__(self):
        self.seq = 0
        self.seq_next = 0
        self.dport = 1234
        self.sport = 1234

    def listen(self):
        pak = sniff(filter="tcp port 1234",count=1)
        pak = pak[0]
        if pak[TCP].flags == "S":
            self.l4 = IP(dst=pak[IP].src)/TCP(sport=self.sport, dport=self.dport)
            self.src = self.l4.src
            self.dst = pak[IP].src
            self.send_syn_ack_server(pak)
        else:
            self.listen()

    def match_packet(self, pkt):
        if pkt.haslayer(IP) and pkt[IP].dst == self.l4[IP].src and pkt.haslayer(TCP) and pkt[TCP].dport == self.sport and pkt[TCP].ack == self.seq_next:
           return True
        return False

    def _sr1(self, pkt):
        send(pkt)
        ans = sniff(filter="tcp port 1234",lfilter=self.match_packet,count=1,timeout=1)
        return ans[0] if ans else None

    def handle_recv(self, pkt):
        if pkt and pkt.haslayer(IP) and pkt.haslayer(TCP):
            if pkt[TCP].flags & 0x3f == 0x10:   # ACK
                print("Connection Established")
                return None
        
        return None

    def send_syn_ack_server(self, rcvsynpkt):
        self.l4[TCP].flags = "SA"
        self.l4[TCP].seq = random.randrange(0,2**32)
        self.l4[TCP].ack = rcvsynpkt[TCP].seq + 1
        self.seq_next = self.l4[TCP].seq + 1
        response = self._sr1(self.l4)
        self.l4[TCP].seq += 1
        return self.handle_recv(response)
    

    def recvdata(self):
        pkt = sniff(filter="tcp port 1234",count=1)
        return bytes(pkt[0][TCP].payload)
    
    def senddata(self, data):
        time.sleep(1)
        pkt = IP(dst=self.dst)/TCP(sport=self.sport, dport=self.dport, flags="PA", seq=random.randrange(0,2**32))
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


def checkWin():
    global moves
    if moves >= 5:
        if theBoard['7'] == theBoard['8'] == theBoard['9'] != ' ': # across the top
            return theBoard['7']
        elif theBoard['4'] == theBoard['5'] == theBoard['6'] != ' ': # across the middle
            return theBoard['4']
        elif theBoard['1'] == theBoard['2'] == theBoard['3'] != ' ': # across the bottom
            return theBoard['1']
        elif theBoard['1'] == theBoard['4'] == theBoard['7'] != ' ': # down the left side
            return theBoard['1']
        elif theBoard['2'] == theBoard['5'] == theBoard['8'] != ' ': # down the middle
            return theBoard['2']
        elif theBoard['3'] == theBoard['6'] == theBoard['9'] != ' ': # down the right side
            return theBoard['3']
        elif theBoard['7'] == theBoard['5'] == theBoard['3'] != ' ': # diagonal
            return theBoard['7']
        elif theBoard['1'] == theBoard['5'] == theBoard['9'] != ' ': # diagonal
            return theBoard['1']
    if moves == 9:
        return '-'
    return ' '

if __name__ == '__main__':
    conn = TcpHandshakeServer()
    conn.listen()
    conn.senddata(public_key.exportKey())
    print("Client Public Key: ")
    clpk = conn.recvdata().decode('utf-8')
    print(clpk)
    client_public_key = RSA.importKey(clpk)
    print("\nServer Private Key: ")
    print(private_key.exportKey().decode('utf-8'))
    global encryptor
    encryptor = PKCS1_OAEP.new(client_public_key)


    global moves
    moves = 0
    symbolChoice = ['X', 'O']
    mySymbol = random.choice(symbolChoice)
    clientSymbol = 'X' if mySymbol == 'O' else 'O'
    conn.sendDataEnc(clientSymbol)
    print("\nYour symbol is " + mySymbol)
    turn = 'O'
    clientfirst = True
    while True:
        printBoard()
        inp = ''
        if turn == mySymbol:
            clientfirst = False
            turn = 'X' if mySymbol == 'O' else 'O'
            inp = input("Its your turn, input a number: ")
            while True:
                try:
                    if int(inp) < 1 or int(inp) > 9:
                        inp = input("You entered an incorrect number, Try again: ")
                        continue
                    if theBoard[inp] != ' ':
                        inp = input("That place is already filled with " + theBoard[inp] + " Try putting your symbol somewhere else: ")
                        continue
                    theBoard[inp] = mySymbol
                    moves += 1
                    break
                except:
                    inp = input("Please Enter a Number: ")
                    continue
            printBoard()
        win = checkWin()
        if win == '-':
            print("\nTied!")
            conn.sendDataEnc('-' + inp)
            exit()
        if win == mySymbol:
            print("\nYou Won!!")
            conn.sendDataEnc('n' + inp)
            exit()
        print("Waiting for the Client...")
        if clientfirst:
            otherplayercoord = conn.recvDataDec()
        else:
            otherplayercoord = conn.sendDataEnc(inp)
            otherplayercoord = conn.recvDataDec()

        theBoard[otherplayercoord] = turn
        moves += 1
        win = checkWin()
        if win == '-':
            printBoard()
            print("\nTied!")
            conn.sendDataEnc('-' + clientSymbol)
            exit()
        if win == clientSymbol:
            printBoard()
            print("\nYou Lost!!")
            conn.sendDataEnc(clientSymbol)
            exit()

        turn = mySymbol