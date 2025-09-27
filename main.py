# UNSAFE IMPLEMENTATION OF OBSOLETE PROTOCOL SMTP client. (RECREATIONAL PROGRAMMING)
# The purpose is not writing "pretty" code but to understand, more or less, what is SMTP about.
# Also I ,sometimes, use old fashioned python to more or less deeply go into the problems.
# Followed by RFC 5321 (https://datatracker.ietf.org/doc/html/rfc5321).

# SMTP is independent of the particular transmission subsystem and
# requires only a reliable ordered data stream channel.
# Unbelivebly I use TCP from TCP/IP stack for "reliable" data stream flow.

# MTA question RFC 5321 (2.3.3)
# A proper smtp application should definitely act as MTA (even server).
# But for recreational and educational purposes I'll split SMTP as client/server arch.
# After that I'll implement someday relaying logic for smtp servers.
# Probably it would change in forseen future.

# For testing I used aiosmtpd (https://github.com/aio-libs/aiosmtpd) smtp server. Big thanks to developers.
import socket
import logging
import argparse

# Auth module
import hmac
import base64
from email.base64mime import body_encode as encode_base64

from functools import wraps
from typing import override

from consts import *

try:
    import ssl
except ImportError:
    _use_ssl = False
else:
    _use_ssl = True
import smtplib

logging.basicConfig(level=logging.INFO)

class SMTPException(OSError):
    """Base class for all exceptions raised by this module."""

class SMTPClient:

    def __init__(self, arguments: argparse.Namespace): # TODO: Make own abstraction so args could be passed as a lib or cli
        self.sock = self._prepare_client_socket()
        self.arguments = arguments
        self.extensions = []
        self.__connect_to_server()

    # decorator to process server response after every command
    def after_call(func):
        @wraps(func)
        def inner(self, *args, **kwargs):
            result = func(self, *args, **kwargs)
            self._process_server_response()
            return result
        return inner

    def send_smtp_message(self): # TODO: pass args here
        self._send_ehlo()
        self._ext_starttls() # TODO: fallback if wrong downgrade to helo probably
        self._send_ehlo()
        #self._send_noop(it_would_be_ignored_xD="yeah ignored")
        #self._send_help()
        #self._send_verify(self.arguments.sender)
        self._send_mail_from()
        for rcpt in self.arguments.recipients:
            self._send_recipient_to(rcpt)
        self._send_data()
        self._send_data_body(self.arguments.file_path)
        self._send_quit()

    def _prepare_client_socket(self) -> socket.socket:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return self.sock

    def _read_file(self, path: str):
        with open(path) as file:
            return file.read()

    @after_call
    def _send_data_body(self, file_path: str):
        buff: str = self._read_file(file_path)
        message = (
        f"Subject: {self.arguments.subject}{CRLF}"
        f"From: {self.arguments.sender}{CRLF}"
        f"To: {", ".join(rcpt for rcpt in self.arguments.recipients)}{CRLF}"
        f"{CRLF}"
        f"{buff}{CRLF}"
        f"{CRLF}"
        f".{CRLF}"
        )
        self.sock.sendall(message.encode())

    # TODO: Auth command. Although, I didn't found it in specification, I guess I need to implement it
    # as well as ssl.

    @after_call
    def _send_verify(self, user: str):
        self._send_custom_msg(b"VRFY" + bSP + user.encode() + bCRLF)

    @after_call
    def _send_expand(self, command: str): # COULD NOT TEST FOR THE MOMENT
        self._send_custom_msg(b"EXPN" + bSP + command.encode() + bCRLF)

    @after_call
    def _send_noop(self, it_would_be_ignored_xD=""): # RFC 5321 (4.1.1.9 NOOP)
        detail: bytes = f"{SP}{it_would_be_ignored_xD}".encode() if it_would_be_ignored_xD else b""
        self._send_custom_msg(b"NOOP" + detail + bCRLF)

    @after_call
    def _send_help(self, command=""):
        detail: bytes = f"{SP}{command}".encode() if command else b""
        self._send_custom_msg(b"HELP" + detail + bCRLF)

    @after_call
    def _send_reset(self):
        self._send_custom_msg(b"RSET" + bCRLF)

    @after_call
    def _send_quit(self):
        self._send_custom_msg(b"QUIT" + bCRLF)

    @after_call
    def _send_mail_from(self):
        self._send_custom_msg(f"MAIL FROM:<{args.sender}>".encode() + bCRLF)

    # TODO add multiple recipients support
    @after_call
    def _send_recipient_to(self, rcpt: str):
        self._send_custom_msg(f"RCPT TO:<{rcpt}>".encode() + bCRLF)

    @after_call
    def _send_hello(self):
        self._send_custom_msg(b"HELO" + bSP + self.arguments.host.encode()+ bCRLF)

    def _send_ehlo(self): # TODO: collect stuff from server after ehlo and check later if extensions supported
        self._send_custom_msg(b"EHLO" + bSP + self.arguments.host.encode() + bCRLF)
        lines, _ = self._process_server_response()
        self.extensions = [line[4:].lower() for line in lines][1:]
        logging.info(f"EXTENSIONS FOUND: {self.extensions}")

    @after_call
    def _send_data(self):
        self._send_custom_msg(b"DATA" + bCRLF)

    def _send_custom_msg(self, msg: bytes):
        self.sock.send(msg)
        logging.info(f"SENT: {msg.decode().strip(CRLF)}")

    def _ext_starttls(self):
        if not "starttls" in self.extensions:
            raise SMTPException(
                "STARTTLS extension not supported by server.")
        self._send_custom_msg(b"STARTTLS" + bCRLF)
        lines, _ = self._process_server_response()
        context = ssl._create_stdlib_context()
        self.sock = context.wrap_socket(self.sock)

    def _process_server_response(self) -> tuple[list[str], bytes]:
        lines, buff = self._read_response()
        for line in lines:
            code = int(line[:3])
            reply_code = SmtpReplyCode.from_code(code)

            if code >= 400:
                self.__handle_exception(code)

        logging.info("RECEIVED: " + buff.decode().strip(CRLF))
        #logging.debug("EXPLAIN: " + f"{reply_code.code} {reply_code.reason}")

        return lines, buff

    def __connect_to_server(self) -> None:
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
        raise SMTPException(error_str)
    
    def __parse_resp_code(self, res: bytes):
        resp = res.decode()
        try:
            return int(resp.split(" ", 1)[0])
        except Exception:
            return int(resp.split("-", 1)[0])

    def _read_response(self) -> tuple[list[str], bytes]:
        buffer = b""
        while True:
            chunk = self.sock.recv(DEFAULT_BUFFER)
            if not chunk:
                break
            buffer += chunk
            lines = buffer.decode().split(CRLF)
            if lines[-2][:3].isdigit() and lines[-2][3:4] == " ":
                break
        return [line for line in buffer.decode().split(CRLF) if line], buffer


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        buff = b""
        # Inform server that we would not write any data
        self.sock.shutdown(socket.SHUT_WR)
        # Exhaust buffer
        while True:
            buff = self.sock.recv(DEFAULT_BUFFER)
            if not buff:
                break
        self.sock.close()

# if _use_ssl:
#     class SSLSMTPWrapper(SMTPClient):

#         def __init__(self, arguments, context=None):
#             if context is None:
#                 context = ssl._create_stdlib_context()
#             self.context = context

#             super().__init__(arguments)

#         @override
#         def _prepare_client_socket(self):
#             self.sock = super()._prepare_client_socket()
#             self.sock = self.context.wrap_socket(self.sock)
#             return self.sock

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--recipients", nargs="+")
    parser.add_argument("--sender")
    parser.add_argument("--subject")
    parser.add_argument("--file_path")
    args = parser.parse_args()

    for rcpt in args.recipients:
        if not email_validation_regex.match(rcpt):
            raise Exception("Provided recipient email is incorrect " + rcpt)

    if not email_validation_regex.match(args.sender):
        raise Exception("Provided sender email is incorrect")

    # if _use_ssl:
    #     client = SSLSMTPWrapper(args)
    # else:
    client = SMTPClient(args)

    with SMTPClient(args) as smtp_cli:
        smtp_cli.send_smtp_message()
