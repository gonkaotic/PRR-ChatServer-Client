import tcp_constants as tcp
import socket


class ProtocolError(Exception):
    pass


class NetworkFormatManager:

    def __init__(self, separator: str = tcp.SEPARATOR, encoding: str = tcp.ENCODING):
        self.separator = separator
        self.encoding = encoding

    def generate_formated_network_message(self, protocol: int, *args):
        # Returns encoded messages properly formated
        network_message = str(protocol) + self.separator
        for arg in args:
            if arg != '':
                network_message += self.decode_msg(arg) + self.separator

        # Eliminates extra separator
        network_message = network_message[:-1]
        if network_message[-1] != '\n':
            network_message = network_message + '\n'

        return self.encode_msg(network_message)

    def get_protocol(self, msg: bytes):
        # Returns decoded protocol and the rest of the message
        msg = self.decode_msg(msg)
        try:
            parameters = self.separate_parameters(msg)
            protocol = int(parameters[0])
            return protocol, parameters[1]
        except ValueError:
            raise ProtocolError()

    def separate_parameters(self, msg: str, divisions: int = 2):
        if msg[-1] == '|':
            raise ProtocolError("Last character can't be a pipe (|)")
        parameters = []
        if divisions < 2:
            divisions = 2
        for i in range(1, divisions):
            try:
                separator_pos = msg.index(self.separator)
                parameters.append(msg[:separator_pos])
                msg = msg[separator_pos+1:]
            except ValueError:
                break
        parameters.append(msg)
        return parameters

    def encode_msg(self, msg: str):
        if isinstance(msg, str):
            msg = msg.encode(self.encoding)
        return msg

    def decode_msg(self, msg: bytes):
        if isinstance(msg, bytes):
            try:
                msg = msg.decode(self.encoding)
            except UnicodeDecodeError:
                pass
            return msg
        return str(msg)


class NetworkSender:

    def __init__(self, formatter: NetworkFormatManager):
        self.formatter = formatter

    def send_to_all(self, receivers: list, protocol: int, *args):
        if isinstance(receivers, list):
            for client in receivers:
                self.send_to(client, protocol, *args)
        else:
            self.send_to(receivers, protocol, *args)

    def send_to(self, sock: socket.socket, protocol: int, *args):
        network_msg = self.formatter.generate_formated_network_message(protocol, *args)
        output_stream = self.get_output_stream(sock)
        output_stream.write(network_msg)
        output_stream.flush()
        pass

    def get_output_stream(self, s: socket.socket, binary=True):
        if not isinstance(s, socket.socket) or s.proto == socket.SOCK_STREAM:
            raise TypeError

        if binary:
            modifier = 'b'
        else:
            modifier = ''

        output_stream = s.makefile('w' + modifier)
        return output_stream

    def get_input_stream(self, s: socket.socket, binary=True):
        if not isinstance(s, socket.socket) or s.proto == socket.SOCK_STREAM:
            raise TypeError

        if binary:
            modifier = 'b'
        else:
            modifier = ''

        output_stream = s.makefile('r' + modifier)
        return output_stream

    def get_IO_streams(self, s: socket.socket, binary=True):
        return self.get_input_stream(s, binary), self.get_output_stream(s, binary)


