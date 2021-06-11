import unittest, socket
from serv7 import Server
import tcp_constants as tcp
import Backbone as bbn

class MyTestCase(unittest.TestCase):

    def test_formatter_can_get_parameters(self):
        formatter = bbn.NetworkFormatManager("|")
        parameters = formatter.separate_parameters("hola|como")
        self.assertEqual(["hola", "como"], parameters)

    def test_formatter_can_get_parameters_2(self):
        formatter = bbn.NetworkFormatManager("|")
        parameters = formatter.separate_parameters("como|estas")
        self.assertEqual(["como", "estas"], parameters)

    def test_formatter_can_get_parameters_3(self):
        formatter = bbn.NetworkFormatManager("|")
        parameters = formatter.separate_parameters("como|estas|tu", 2)
        self.assertEqual(["como", "estas|tu"], parameters)

    def test_formatter_has_an_error_if_last_charcter_is_pipe(self):
        formatter = bbn.NetworkFormatManager("|")
        with self.assertRaises(bbn.ProtocolError):
            parameters = formatter.separate_parameters("como|estas|tu|", 3)

    def test_formatter_can_get_protocol(self):
        formatter = bbn.NetworkFormatManager("|")
        protocol, rest = formatter.get_protocol(b"1|hola")
        self.assertEqual(1, protocol)

    def test_formatter_can_generate_formatted_messages(self):
        formatter = bbn.NetworkFormatManager("|")
        msg = formatter.generate_formated_network_message(1, "username", "password")
        self.assertEqual(b"1|username|password\n", msg)

    def test_formatter_can_generate_formatted_messages_1(self):
        formatter = bbn.NetworkFormatManager("|")
        msg = formatter.generate_formated_network_message(1, "user", "msg")
        self.assertEqual(b"1|user|msg\n", msg)

    def test_formatter_can_generate_formatted_messages_without_adding_unnecesary_lines(self):
        formatter = bbn.NetworkFormatManager("|")
        msg = formatter.generate_formated_network_message(1, "user", "msg\n")
        self.assertEqual(b"1|user|msg\n", msg)

    def test_formatter_encodes_strings(self):
        formatter = bbn.NetworkFormatManager("|")
        encoded = formatter.encode_msg("Hello")
        self.assertEqual(b"Hello", encoded)

    def test_formatter_encodes_strings_1(self):
        formatter = bbn.NetworkFormatManager("|")
        encoded = formatter.encode_msg("Hellous")
        self.assertEqual(b"Hellous", encoded)

    def test_formatter_doesnt_encode_bytes(self):
        formatter = bbn.NetworkFormatManager("|")
        encoded = formatter.encode_msg(b"Hello")
        self.assertEqual(b"Hello", encoded)

    def test_formatter_decodes_bytes(self):
        formatter = bbn.NetworkFormatManager("|")
        decoded = formatter.decode_msg(b"Hello")
        self.assertEqual("Hello", decoded)

    def test_formatter_decodes_bytes_1(self):
        formatter = bbn.NetworkFormatManager("|")
        decoded = formatter.decode_msg(b"Hellous")
        self.assertEqual("Hellous", decoded)

    def test_formatter_doesnt_decode_strings(self):
        formatter = bbn.NetworkFormatManager("|")
        decoded = formatter.decode_msg("Hello")
        self.assertEqual("Hello", decoded)

if __name__ == '__main__':
    unittest.main()
