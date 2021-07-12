import socket, os, sys, syslog, time, hashlib
from select import select
import tcp_constants as tcp
import Backbone as bbn
import argparse

class Server:

    def __init__(self, ip_address=tcp.DEFAULT_ADDRESS, port=tcp.DEFAULT_PORT, backlog=5, is_daemon=False):
        self.ip_address = ip_address
        self.port = port
        self.backlog = backlog
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serving_sockets = [self.server_socket]

        def log_function_1(msg):
            if msg.decode()[-1] != '\n':
                msg += b'\n'
            os.write(sys.stderr.fileno(), msg)
        log_function = log_function_1

        self.is_daemon = is_daemon
        if is_daemon:
            self.daemonize()

            def sys_log_function(msg, priority=syslog.LOG_INFO):
                syslog.syslog(priority, msg.decode())
            log_function = sys_log_function

        self.server_logic = ServerLogic(self.serving_sockets, log_function)
        pass

    def daemonize(self):
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            os.write(2, f"Fork #1 failed: {e.errno} {e.strerror}".encode())
            sys.exit(1)

        os.chdir("/")
        os.setsid()
        os.umask(0)

        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            os.write(2, f"Fork #2 failed: {e.errno} {e.strerror}".encode())
            sys.exit(1)

        os.close(sys.stdin.fileno())
        os.close(sys.stdout.fileno())
        os.close(sys.stderr.fileno())

        syslog.openlog()

    def start(self):
        self.server_socket.bind((self.ip_address, self.port))
        self.server_socket.listen(self.backlog)
        self.server_logic.log_event(f"Server ready in address: {self.ip_address}:{self.port}\n".encode())
        while True:
            sockets_to_read_from, _, _ = select(self.serving_sockets, [], [])
            for sock in sockets_to_read_from:
                if sock is self.server_socket:
                    self.server_logic.new_connection(self.server_socket.accept())
                else:
                    self.serve(sock)
        pass

    def serve(self, sock):
        input_stream = self.get_input_stream(sock)
        data = input_stream.readline()
        self.server_logic.process(sock, data)

    def get_input_stream(self, sock: socket.socket, binary=True):
        if not isinstance(sock, socket.socket) or sock.proto == socket.SOCK_STREAM:
            raise TypeError

        if binary:
            modifier = 'b'
        else:
            modifier = ''

        input_stream = sock.makefile('r' + modifier)
        return input_stream


class ServerLogic:

    DEFAULT_ROOM = "Hall"
    KW_CHATROOM = "chatroom"
    KW_USERNAME = "username"

    def __init__(self, serving_sockets, log_function):
        self.serving_sockets = serving_sockets
        self.connected_clients = {}
        self.chatrooms = {self.DEFAULT_ROOM: []}
        self.authenticator = Authenticator(tcp.LOGIN_INFO_FILE)
        self.formatter = bbn.NetworkFormatManager()
        self.sender = bbn.NetworkSender(self.formatter)
        self.log_event = log_function

    def process(self, sock: socket.socket, msg: bytes):

        if msg == b'':
            self.disconnection(sock)
        else:
            protocol, rest = self.formatter.get_protocol(msg)
            if sock in self.connected_clients:
                if protocol == tcp.PROTOCOL_MSG:
                    self.protocol_msg(rest, sock)
                elif protocol == tcp.PROTOCOL_SHUTDOWN:
                    self.protocol_shutdown(sock)
                elif protocol == tcp.PROTOCOL_JOIN_ROOM:
                    self.protocol_join_room(rest[:-1], sock)
                elif protocol == tcp.PROTOCOL_LIST_ROOMS:
                    self.protocol_list_rooms(sock)
                elif protocol == tcp.PROTOCOL_LIST_USERS:
                    self.protocol_list_users(sock)
                elif protocol == tcp.PROTOCOL_PRIVATE_MSG:
                    self.protocol_private_msg(rest, sock)
                elif protocol == tcp.PROTOCOL_KICK_USER:
                    self.protocol_kick_user(rest[:-1], sock)
                elif protocol == tcp.PROTOCOL_DELETE_ROOM:
                    self.protocol_delete_room(rest[:-1], sock)
                else:
                    # we would have to answer a tcp.PROTOCOL_UNKNONW
                    pass
            else:
                if protocol == tcp.PROTOCOL_LOGIN:
                    try:
                        self.protocol_login(rest, sock)
                    except LoginException as e:
                        self.log_event(str(e).encode())
                        self.sender.send_to(sock, tcp.PROTOCOL_LOGIN_DENY, rest)
                        self.disconnection(sock)
                        sock.close()
                else:
                    # not respecting protocol: kick them out
                    self.disconnection(sock)
                    sock.close()

    def protocol_shutdown(self, sock):
        self.log_event(f"Shutting down signal sent by: {self.connected_clients[sock][self.KW_USERNAME]}\n".encode())
        for client in self.serving_sockets:
            client.close()
        sys.exit(0)
        pass

    def protocol_msg(self, msg, sender):
        username = self.connected_clients[sender][self.KW_USERNAME]
        room = self.connected_clients[sender][self.KW_CHATROOM]
        self.log_event(f"Chatroom\"{room}\" => {username}:{msg}".encode())
        self.sender.send_to_all(self.chatrooms[room], tcp.PROTOCOL_MSG, username, msg)

    def protocol_login(self, login_info, connection):
        try:
            first_separator = login_info.index(tcp.SEPARATOR)
            username = login_info[:first_separator]
            password = login_info[first_separator+1:-1]
        except ValueError:
            raise LoginException("Client didn't send the right info\n\t"+login_info+"\n")

        if username in self.connected_clients.values():
            raise LoginException(f"username \"{username}\" already in use\n")
        else:
            if self.authenticator.authenticate_user(username, password):
                self.connected_clients[connection] = {self.KW_USERNAME: username, self.KW_CHATROOM: ''}
                msg = f"{username} has joined the server.\n"
                self.log_event(msg.encode())
                self.sender.send_to(connection, tcp.PROTOCOL_LOGIN_ACCEPT, login_info)
                # I have decided everyone joins the hall when they connect
                self.protocol_join_room(self.DEFAULT_ROOM, connection)
            else:
                raise LoginException(f"Wrong password for \"{username}\": {password}")

        pass

    def protocol_join_room(self, room, connection):
        usr_name = self.connected_clients[connection][self.KW_USERNAME]
        previous_chatroom = self.connected_clients[connection][self.KW_CHATROOM]
        if previous_chatroom != '':
            self.log_event(f"{usr_name} leaves {previous_chatroom} and joins {room}\n".encode())
            self.chatrooms[previous_chatroom].remove(connection)
            self.sender.send_to_all(self.chatrooms[previous_chatroom], tcp.PROTOCOL_LEAVE_ROOM, usr_name)

        if not(room in self.chatrooms):
            # I decided that the way to create a room is joining a room that doesn't exist
            # at least for now
            self.chatrooms[room] = []
            self.log_event(f"Chatroom \"{room}\" was created by {usr_name}\n".encode())
        # Don't ask me why, but when the previous room is '' this small wait is necessary
        if previous_chatroom == '':
            time.sleep(0.5)
        self.connected_clients[connection][self.KW_CHATROOM] = room
        self.chatrooms[room].append(connection)
        self.sender.send_to_all(self.chatrooms[room], tcp.PROTOCOL_JOIN_ROOM, usr_name)

    def protocol_list_rooms(self, sock):
        self.log_event(f"{self.connected_clients[sock][self.KW_USERNAME]} is asking about rooms\n".encode())
        info = []
        for room in self.chatrooms:
            info.append(room)
            info.append(len(self.chatrooms[room]))
        self.sender.send_to(sock, tcp.PROTOCOL_LIST_ROOMS, *info)

    def protocol_list_users(self, sock):
        self.log_event(f"{self.connected_clients[sock][self.KW_USERNAME]} is asking about users\n".encode())
        info = []
        for user in self.connected_clients.values():
            info.append(user[self.KW_USERNAME])
        self.sender.send_to(sock, tcp.PROTOCOL_LIST_USERS, *info)

    def protocol_kick_user(self, user, sock):
        receiver = None
        for client in self.connected_clients:
            if self.connected_clients[client][self.KW_USERNAME] == user:
                receiver = client
                break
        sender_name = self.connected_clients[sock][self.KW_USERNAME]
        if receiver is None:
            self.log_event((f"{sender_name} tried to kick {user} but user was not found\n").encode())
            self.sender.send_to(sock, tcp.PROTOCOL_USER_NOT_FOUND, user)
        else:
            self.log_event((f"{sender_name} kicks {user}\n").encode())
            self.disconnection(receiver)
            receiver.close()

    def protocol_private_msg(self, rest, sock):
        try:
            first_separator = rest.index(tcp.SEPARATOR)
            receiver_name = rest[:first_separator]
            msg = rest[first_separator + 1:-1]
            receiver = None
            for client in self.connected_clients:
                if self.connected_clients[client][self.KW_USERNAME] == receiver_name:
                    receiver = client
                    break
            sender_name = self.connected_clients[sock][self.KW_USERNAME]
            if receiver is None:
                self.log_event((f"{sender_name} tried to send this to {receiver_name} " +
                                f"but username was not found: {msg}\n").encode())
                self.sender.send_to(sock, tcp.PROTOCOL_USER_NOT_FOUND, receiver_name, msg)
            else:
                self.log_event(f"{sender_name} says to {receiver_name}: {msg}\n".encode())
                self.sender.send_to(receiver, tcp.PROTOCOL_PRIVATE_MSG, sender_name, msg)
        except ValueError:
            # should send a message to inform there was an error
            pass

    def protocol_delete_room(self, room, sock):
        orderer_name = self.connected_clients[sock][self.KW_USERNAME]
        if room in self.chatrooms:
            self.log_event(f"{orderer_name} deleted room \"{room}\". Moving everyone to default room".encode())
            for client in self.chatrooms[room]:
                # Next line is so that they don't leave a message behind as they leave the room
                self.connected_clients[client][self.KW_CHATROOM] = ''
                self.sender.send_to(client, tcp.PROTOCOL_DELETE_ROOM, room)
                self.protocol_join_room(self.DEFAULT_ROOM, client)
            del self.chatrooms[room]
        else:
            self.log_event(f"{orderer_name} tried to delete room \"{room}\" but room was not found".encode())
            self.sender.send_to(sock, tcp.PROTOCOL_ROOM_NOT_FOUND, room)

    def disconnection(self, connection):
        self.serving_sockets.remove(connection)
        if connection in self.connected_clients:
            usr_name = self.connected_clients[connection][self.KW_USERNAME]
            self.log_event(f"{usr_name} left the chat\n".encode())
            chatroom = self.connected_clients[connection][self.KW_CHATROOM]
            self.chatrooms[chatroom].remove(connection)
            del self.connected_clients[connection]
            self.sender.send_to_all(self.chatrooms[chatroom], tcp.PROTOCOL_LEAVE_ROOM, usr_name)
        pass

    def new_connection(self, connection):
        self.log_event(f"\nReceived a connection from: {connection[1]}\n".encode())
        self.serving_sockets.append(connection[0])

    pass


class Authenticator:

    def __init__(self, login_file):
        self.login_file = login_file

    #return True if there was no previous username, false if there is any problem
    def add_user(self, username, password):
        with open(self.login_file, 'ab') as file:
            file.write((username + "\n" + self.encrypt(password) + "\n").encode())
        return True

    #return True if the password and username match with those in the file
    def authenticate_user(self, username, password):
        with open(self.login_file, 'rb') as file:
            lines = file.readlines()
            for i, line in enumerate(lines):
                if line[:-1].decode() == username:
                    return lines[i+1][:-1].decode() == self.encrypt(password)

        return False

    def encrypt(self, data):
        sha_signature = hashlib.sha256(data.encode()).hexdigest()
        return sha_signature


class LoginException(Exception):
    pass


def main():
    parser = argparse.ArgumentParser(description="Run a chat room server")
    parser.add_argument(
        "-a",
        "--address",
        default=tcp.DEFAULT_ADDRESS,
        help="Specify the IP address on which the server listens",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=tcp.DEFAULT_PORT,
        help="Specify the port on which the server listens",
    )
    parser.add_argument(
        "-b",
        "--backlog",
        type=int,
        default=-1,
        help="Specify the backlog of the server(clients that can wait while others are being attended)",
    )
    parser.add_argument(
        "-d",
        "--daemon",
        action='store_true',
        help="Run the server as a demon",
    )
    args = parser.parse_args()
    if args.backlog != -1:
        server = Server(ip_address=args.address, port=args.port, is_daemon=args.daemon, backlog=args.backlog)
    else:
        server = Server(ip_address=args.address, port=args.port, is_daemon=args.daemon)
    server.start()


if __name__ == "__main__":
    main()