import tcp_constants as tcp
import os, socket, sys, select
import Backbone

class CommandException(Exception):
    pass


class Client():

    def __init__(self, username, password, ip=tcp.DEFAULT_ADDRESS, port=tcp.DEFAULT_PORT):
        self.username = username
        self.password = password
        self.ip_address = ip
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.input_stream = None
        self.output_stream = None
        self.formatter = Backbone.NetworkFormatManager()
        self.sender = Backbone.NetworkSender(self.formatter)

    def process_server_input(self, protocol, rest=''):
        if protocol == tcp.PROTOCOL_MSG:
            first_separator = rest.index(tcp.SEPARATOR)
            sender_name = rest[:first_separator]
            msg = rest[first_separator + 1:]
            if sender_name != self.username:
                os.write(1, (sender_name + ": " + msg).encode())

        elif protocol == tcp.PROTOCOL_SERVER_CLOSING:
            os.write(1, b"Server is closing, so we are closing the connection\n")
            sys.exit(0)

        elif protocol == tcp.PROTOCOL_LOGIN_DENY:
            os.write(1, b"There was an error logging in\n")
            sys.exit(0)

        elif protocol == tcp.PROTOCOL_LOGIN_ACCEPT:
            os.write(1, b"Login accepted\n")

        elif protocol == tcp.PROTOCOL_LIST_ROOMS:
            info = rest[:-1].split(tcp.SEPARATOR)
            msg = ''.encode()
            for i, data in enumerate(info):
                if i % 2:
                    msg += data.encode() + b' users\n'
                else:
                    msg = msg + b'\t' + data.encode() + b' =>'
            os.write(1, msg)

        elif protocol == tcp.PROTOCOL_LIST_USERS:
            info = rest[:-1].split(tcp.SEPARATOR)
            msg = ""
            for data in info:
                msg += "\t" + data + "\n"
            os.write(1, msg.encode())

        elif protocol == tcp.PROTOCOL_PRIVATE_MSG:
            first_separator = rest.index(tcp.SEPARATOR)
            sender_name = rest[:first_separator]
            msg = rest[first_separator + 1:-1]
            os.write(1, (sender_name + " whispered to you: " + msg + '\n').encode())

        elif protocol == tcp.PROTOCOL_JOIN_ROOM:
            user_name = rest[:-1]
            if user_name == self.username:
                os.write(1, f"You have joined the room\n".encode())
            else:
                os.write(1, f"{user_name} has joined the room\n".encode())

        elif protocol == tcp.PROTOCOL_LEAVE_ROOM:
            user_name = rest[:-1]
            os.write(1, f"{user_name} has left the room\n".encode())

        elif protocol == tcp.PROTOCOL_USER_NOT_FOUND:
            user_name = rest[:-1]
            os.write(1, f"{user_name} not found\n".encode())

        elif protocol == tcp.PROTOCOL_DELETE_ROOM:
            room = rest[:-1]
            os.write(1, f'{room} chatroom was deleted, moving you to default room\n'.encode())

        elif protocol == tcp.PROTOCOL_ROOM_NOT_FOUND:
            room = rest[:-1]
            os.write(1, f'{room} chatroom not found\n'.encode())

        pass

    def process_user_input(self, msg):
        protocol = tcp.PROTOCOL_MSG
        if msg[0] == '/':
            try:
                data = msg[1:].split()
                keyword = data[0]
                if keyword == 'chatroom':
                    command = data[1]
                    if command == 'join':
                        protocol = tcp.PROTOCOL_JOIN_ROOM
                        msg = data[2] + "\n"

                    elif command == 'list':
                        protocol = tcp.PROTOCOL_LIST_ROOMS
                        msg = '\n'

                    elif command == 'delete':
                        protocol = tcp.PROTOCOL_DELETE_ROOM
                        msg = data[2] + "\n"

                    else:
                        raise CommandException("command for chatroom not found")

                elif keyword == 'users':
                    protocol = tcp.PROTOCOL_LIST_USERS

                elif keyword == 'dm':
                    protocol = tcp.PROTOCOL_PRIVATE_MSG
                    msg = ' '.join(data[1:])
                    try:
                        pos = msg.index(':')
                        user = msg[:pos]
                        msg = msg[pos + 1:] + '\n'
                        msg = [user, msg]
                    except ValueError:
                        raise CommandException(b"You need to write : after the name of the person you want to dm")

                elif keyword == "shutdown":
                    protocol = tcp.PROTOCOL_SHUTDOWN
                    msg = '\n'

                elif keyword == "kick":
                    protocol = tcp.PROTOCOL_KICK_USER
                    msg = ' '.join(data[1:]) + "\n"

            except IndexError:
                raise CommandException(b"You need more parameters for that")
        return protocol, msg
        pass

    def connect(self, ip_address=None, port=None):

        if ip_address is None: ip_address = self.ip_address
        else: self.ip_address = ip_address
        if port is None: port = self.port
        else: self.port = port
        try:
            self.client_socket.connect((ip_address, port))
        except ConnectionRefusedError as e:
            os.write( 2, b"Server refused the connection\n")
            sys.exit(-1)

        self.input_stream = self.sender.get_input_stream(self.client_socket)

        self.sender.send_to(self.client_socket, tcp.PROTOCOL_LOGIN, self.username, self.password)
        while True:
            try:
                readers, _, _ = select.select([sys.stdin, self.input_stream], [], [])
                for reader in readers:
                    if reader is self.input_stream:
                        line = self.input_stream.readline()
                        if line == b'':
                            protocol = tcp.PROTOCOL_SERVER_CLOSING
                            self.process_server_input(protocol)
                        else:
                            try:
                                protocol, rest = self.formatter.get_protocol(line)
                                self.process_server_input(protocol, rest)
                            except Backbone.ProtocolError:
                                os.write(2, f"Couldn't process \"{line}\". Ignoring it\n".encode())
                                continue
                    else:
                        msg = sys.stdin.readline()
                        if msg != '\n':
                            try:
                                protocol, msg = self.process_user_input(msg)
                            except CommandException as e:
                                os.write(2, str(e).encode())
                                continue
                            if isinstance(msg, list):
                                self.sender.send_to(self.client_socket, protocol, *msg)
                            else:
                                self.sender.send_to(self.client_socket, protocol, msg)

            except KeyboardInterrupt:
                os.write(1, b"\nDisconnecting from server.")
                sys.exit(0)


if __name__ == "__main__":
    username = ''
    password = ''
    ip_address = tcp.DEFAULT_ADDRESS
    port = tcp.DEFAULT_PORT
    for i, argument in enumerate(sys.argv):
        if argument[0] == '-':
            option = argument[1]
            try:
                if option == 'a': #address
                    ip_address = sys.argv[i+1]
                elif option == 'p': #port
                    port = int(sys.argv[i+1])
                elif option == 'u': #username
                    username = sys.argv[i+1]
                elif option == 'c':  # password
                    password = sys.argv[i + 1]
            except IndexError:
                os.write(2, b'Option \''+ option+'\' needs a parameter')
                sys.exit(-1)
    if username != '' and password != '':
        client = Client(username=username, password=password, ip=ip_address, port=port)
        client.connect()
    else:
        os.write(2, b"A username and a password are required\n")




