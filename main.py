# UNSAFE IMPLEMENTATION OF OBSOLETE PROTOCOL SMTP client. (RECREATIONAL PROGRAMMING)
# The purpose is not writing "pretty" code but to understand, more or less, what is SMTP about.
# Also I ,sometimes, use old fashioned python to more or less deeply go into the problems.
# Followed by RFC 5321 (https://datatracker.ietf.org/doc/html/rfc5321).

# SMTP is independent of the particular transmission subsystem and
# requires only a reliable ordered data stream channel.

# MTA question RFC 5321 (2.3.3)
# A proper smtp application should definitely act as MTA (even server).
# But for recreational and educational purposes I'll split SMTP as client/server arch.
# After that i'll implement someday relaying logic for smtp servers
# Probably it would change in forseen future
import socket
import io
import datetime
import logging
import argparse

from functools import wraps

from consts import *

logging.basicConfig(level=logging.INFO)
shutdown_flag = False

def handle_sigint(signum, frame):
    global shutdown_flag
    logging.info("[!] Caught SIGINT, shutting down...")
    shutdown_flag = True

class SMTPClient:

    def __init__(self, arguments: argparse.Namespace):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.arguments = arguments
        self.__connnect_to_server()

    # decorator to process server response after every command
    def after_call(func):
        @wraps(func)
        def inner(self, *args, **kwargs):
            result = func(self, *args, **kwargs)
            self.__process_server_response()
            return result
        return inner

    def send_smtp_message(self):
        self._send_ehlo()
        self._send_mail_from()
        self._send_mail_to()
        self._send_data()

    def _read_file(self, path: str):
        pass

    def _prepare_body(self, file_str: str):
        pass

    @after_call
    def _send_mail_from(self):
        self._send_custom_msg(f"MAIL FROM: <{args.sender}>".encode() + bSP + bCRLF)

    # TODO add multiple recipients support
    @after_call
    def _send_mail_to(self):
        self._send_custom_msg(f"MAIL TO: <{args.recipient}>".encode() + bSP + bCRLF)

    @after_call
    def _send_helo(self):
        self._send_custom_msg(b"HELO" + bSP + self.arguments.host.encode() + bSP + bCRLF)

    @after_call
    def _send_ehlo(self):
        self._send_custom_msg(b"EHLO" + bSP + self.arguments.host.encode() + bSP + bCRLF)

    @after_call
    def _send_data(self):
        self._send_custom_msg(b"DATA" + bCRLF)

    def _send_custom_msg(self, msg: bytes):
        self.sock.send(msg)
        logging.info(f"SENT: {msg.decode().strip(CRLF)}")

    def __process_server_response(self) -> None:
        resp = self.sock.recv(DEFAULT_BUFFER)
        code = self.__parse_resp_code(resp)

        if code >= 400:
            self.__handle_exception(code)

        reply_code = SmtpReplyCode.from_code(code)
        logging.info("RECEIVED: " + f"{reply_code.code} {reply_code.reason}")

    def __connnect_to_server(self) -> None:
        self.sock.connect((args.host, args.port))
        chunk = self.sock.recv(DEFAULT_BUFFER)
        code = int(chunk.decode().split(" ", 1)[0])

        if code != SmtpReplyCode.SERVICE_READY.code:
            self.__handle_exception(code)

        reply_code = SmtpReplyCode.from_code(code)
        logging.info("RECEIVED: " + f"{reply_code.code} {reply_code.reason}")

    def __handle_exception(self, code: int):
        reply_code_member = SmtpReplyCode.from_code(code)
        error_str: str = f"Failed with {reply_code_member.code} code. Reason: {reply_code_member.reason}"
        logging.error(error_str)
        raise Exception(error_str)
    
    def __parse_resp_code(self, res: bytes):
        resp = res.decode()
        try:
            return int(resp.split(" ", 1)[0])
        except Exception:
            return int(resp.split("-", 1)[0])

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        buff = b""
        # Inform server that we would not write any data
        self.sock.shutdown(socket.SHUT_WR)
        # Exhaust buffer
        while buff != b"":
            buff = self.sock.recv(DEFAULT_BUFFER)
        self.sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--recipient")
    parser.add_argument("--sender")
    parser.add_argument("--message_path")
    parser.add_argument("--file_path")
    args = parser.parse_args()

    if not email_validation_regex.match(args.recipient):
        raise Exception("Provided recipient email is incorrect")

    if not email_validation_regex.match(args.sender):
        raise Exception("Provided sender email is incorrect")

    with SMTPClient(args) as smtp_cli:
        smtp_cli.send_smtp_message()

    # sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # sock.connect((args.host, args.port))

    # chunk = sock.recv(DEFAULT_BUFFER)
    # sock.send(b"HELO" + bSP + args.host.encode() + bSP + bCRLF)
    # chunk = sock.recv(DEFAULT_BUFFER)
    # print(chunk)
    # print('=' * 20)
    # sock.send(f"MAIL FROM: <{args.sender}>".encode() + bSP + bCRLF)
    # chunk = sock.recv(DEFAULT_BUFFER)
    # print(chunk)
    # print('=' * 20)
    # sock.send(f"RCPt TO: <{args.recipient}>".encode() + bSP + bCRLF) # THIS CASE INSENSITIVE
    # chunk = sock.recv(DEFAULT_BUFFER)
    # print(chunk)
    # print('=' * 20)
    # sock.send(b"DATA" + bCRLF)
    # chunk = sock.recv(DEFAULT_BUFFER)
    # print(chunk)
    # print('=' * 20)
    # message = (
    # "Subject: Test Mail\r\n"
    # "From: gragonog@gmail.com\r\n"
    # "To: flamelessowo@gmail.com\r\n"
    # "\r\n"
    # "Hello, this is a test message.\r\n"
    # "\r\n" # bCRLF
    # ".\r\n" # b"." + bCRLF
    # )
    # sock.sendall(message.encode())
    # chunk = sock.recv(DEFAULT_BUFFER)
    # print(chunk)
    # print('=' * 20)
    # sock.send(b"QUIT" + bCRLF)
    # chunk = sock.recv(DEFAULT_BUFFER)
    # print(chunk)
    # print('=' * 20)

    # # Close socket correctly
    # sock.shutdown(socket.SHUT_WR)
    # # Exhause buffer
    # while chunk != b"":
    #     chunk = sock.recv(DEFAULT_BUFFER)
    # sock.close()