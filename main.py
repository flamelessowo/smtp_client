# UNSAFE IMPLEMENTATION OF OBSOLETE PROTOCOL SMTP client (and little of ESMPT). (RECREATIONAL PROGRAMMING)
# The purpose is not writing "pretty" code, but to understand, more or less, what is the SMTP protocol.
# Also I ,sometimes, use old fashioned python to, more or less, deeply dive into the problems related to network programming.
# Followed by RFC 5321 (https://datatracker.ietf.org/doc/html/rfc5321).

# SMTP is independent of the particular transmission subsystem and
# requires only a reliable ordered data stream channel.
# Unbelievably, I use the TCP, from TCP/IP stack, for it's "reliable" data stream flow.

# MTA question RFC 5321 (2.3.3)
# A proper smtp application should definitely act as MTA (even server).
# But for recreational and educational purposes I'll split SMTP as client/server arch.
# After that I'll implement, someday, relaying logic for smtp servers.

# For testing I used aiosmtpd (https://github.com/aio-libs/aiosmtpd) as esmtp server. Big thanks to it's developers!
import socket
import logging
import argparse
import ssl

# Auth module
#import hmac
import base64
#from email.base64mime import body_encode as encode_base64

from functools import wraps
from typing import override
from dataclasses import dataclass

from consts import *

logging.basicConfig(level=logging.INFO)

class SMTPException(OSError):
    """Base class for all exceptions raised by this module."""


@dataclass
class SMTPMessage:
    host: str
    port: int
    sender: str
    recipients: list[str]
    subject: str
    file_path: str | None = None
    message_body: str | None = ""
    username: str | None = None
    password: str | None = None


class SMTPClient:

    def __init__(self):
        self.sock = None
        self.extensions = []

    # decorator to process server response after every command
    def after_call(func):
        @wraps(func)
        def inner(self, *args, **kwargs):
            result = func(self, *args, **kwargs)
            self._process_server_response()
            return result
        return inner

    def send_smtp_message(self, message: SMTPMessage):
        self.config = message
        self._connect_to_server()
        if self.config.port == SMTP_TLS_HANDSHAKE_PORT:
            self._send_ehlo()
            self._ext_starttls() # TODO: fallback if wrong downgrade to helo probably
        self._send_ehlo()
        try:
            self._ext_auth_plain(self.config.username, self.config.password)
        except SMTPException:
            self._send_reset()
            self._ext_auth_login(self.config.username, self.config.password)
        #self._send_noop(it_would_be_ignored_xD="yeah ignored")
        #self._send_help()
        #self._send_verify(self.config.sender)
        self._send_mail_from()
        for rcpt in self.config.recipients:
            self._send_recipient_to(rcpt)
        self._send_data()
        self._send_data_body(file_path=self.config.file_path, message_body=self.config.message_body)
        self._send_quit()
        self._cleanup()

    def _cleanup(self):
        if self.sock:
            buff = b""
            # Inform server that we would not write any data
            self.sock.shutdown(socket.SHUT_WR)
            # Exhaust buffer
            while True:
                buff = self.sock.recv(DEFAULT_BUFFER)
                if not buff:
                    break
            self.sock.close()
        self.sock = None
        self.extensions = []

    def _prepare_client_socket(self) -> socket.socket:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return self.sock

    def _read_file(self, path: str):
        with open(path) as file:
            return file.read()

    @after_call
    def _send_data_body(self, file_path: str | None = None, message_body: str | None = ""):
        if file_path:
            buff: str = self._read_file(file_path)
        else:
            buff: str = message_body
        message = (
        f"Subject: {self.config.subject}{CRLF}"
        f"From: {self.config.sender}{CRLF}"
        f"To: {", ".join(rcpt for rcpt in self.config.recipients)}{CRLF}"
        f"{CRLF}"
        f"{buff}{CRLF}"
        f"{CRLF}"
        f".{CRLF}"
        )
        self.sock.sendall(message.encode())

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
        self._send_custom_msg(f"MAIL FROM:<{self.config.sender}>".encode() + bCRLF)

    # TODO add multiple recipients support
    @after_call
    def _send_recipient_to(self, rcpt: str):
        self._send_custom_msg(f"RCPT TO:<{rcpt}>".encode() + bCRLF)

    @after_call
    def _send_hello(self):
        self._send_custom_msg(b"HELO" + bSP + self.config.host.encode()+ bCRLF)

    def _send_ehlo(self): # TODO: collect stuff from server after ehlo and check later if extensions supported
        self._send_custom_msg(b"EHLO" + bSP + self.config.host.encode() + bCRLF)
        lines, _ = self._process_server_response()
        self.extensions = [line[4:].lower() for line in lines][1:]
        logging.info(f"EXTENSIONS FOUND: {self.extensions}")

    @after_call
    def _send_data(self):
        self._send_custom_msg(b"DATA" + bCRLF)

    def _send_custom_msg(self, msg: bytes):
        self.sock.send(msg)
        logging.info(f"SENT: {msg.decode().strip(CRLF)}")

    def _ext_starttls(self): # RFC 3207
        if not "starttls" in self.extensions:
            raise SMTPException(
                "STARTTLS extension not supported by server.")
        self._send_custom_msg(b"STARTTLS" + bCRLF)
        lines, _ = self._process_server_response() # TODO finish
        context = ssl._create_stdlib_context()
        self.sock = context.wrap_socket(self.sock)

# Auth exts, i won't implement only XOAUTH and PLAIN-CLIENTTOKEN on my opinion they obsolete
    def _ext_auth_login(self, issuer: str, password: str): # RFC 4954
        def __process_command():
            lines, _ = self._process_server_response()
            code = int(lines[0].split(" ")[0])
            reply_code = SmtpReplyCode.from_code(code)
            if code >= 400:
                raise SMTPException(f"Auth login error: {reply_code.code} {reply_code.reason}")

        self._send_custom_msg(b"AUTH LOGIN" + bCRLF)
        __process_command()
        
        cmds = [issuer, password]
        for cmd in cmds:
            self._send_custom_msg(base64.b64encode(cmd.encode()) + bCRLF)
            __process_command()
            
    @after_call
    def _ext_auth_plain(self, issuer: str, password: str): # RFC 4954
        auth_string = f"\0{issuer}\0{password}".encode()
        self._send_custom_msg(b"AUTH PLAIN " + base64.b64encode(auth_string) + bCRLF)

    def _ext_auth_xoauth2(self):
        pass

    def _ext_auth_oauthbearer(self):
        pass

    def _process_server_response(self) -> tuple[list[str], bytes]:
        lines, buff = self._read_response()
        for line in lines:
            code = int(line[:3])
            reply_code = SmtpReplyCode.from_code(code)

            if code >= 400:
                self._handle_exception(code)

        logging.info("RECEIVED: " + buff.decode().strip(CRLF))
        #logging.debug("EXPLAIN: " + f"{reply_code.code} {reply_code.reason}")

        return lines, buff

    def _connect_to_server(self) -> None:
        self.sock = self._prepare_client_socket()
        self.sock.connect((self.config.host, self.config.port))
        chunk = self.sock.recv(DEFAULT_BUFFER)
        code = int(chunk.decode().split(" ", 1)[0])

        if code != SmtpReplyCode.SERVICE_READY.code:
            self._handle_exception(code)

        reply_code = SmtpReplyCode.from_code(code)
        logging.info("RECEIVED: " + f"{reply_code.code} {reply_code.reason}")

    def _handle_exception(self, code: int):
        reply_code_member = SmtpReplyCode.from_code(code)
        error_str: str = f"Failed with {reply_code_member.code} code. Reason: {reply_code_member.reason}"
        logging.error(error_str)
        raise SMTPException(error_str)
    
    def _parse_resp_code(self, res: bytes):
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
        self._cleanup()

class SSLSMTPWrapper(SMTPClient):

    def __init__(self, context=None):
        if context is None:
            context = ssl._create_stdlib_context()
        self.context = context

        super().__init__()

    @override
    def _prepare_client_socket(self):
        self.sock = super()._prepare_client_socket()
        self.sock = self.context.wrap_socket(self.sock)
        return self.sock

def send_single_smtp_message(args: SMTPMessage | argparse.Namespace): # TODO refactor, it's really bad as a library rn
    for rcpt in args.recipients:
        if not email_validation_regex.match(rcpt):
            raise Exception("Provided recipient email is incorrect " + rcpt)

    if not email_validation_regex.match(args.sender):
        raise Exception("Provided sender email is incorrect")

    if args.port not in [SMTP_SSL_PORT, SMTP_TLS_HANDSHAKE_PORT]:
        raise Exception("Connections on not well-known ports not supoprted")

    message = SMTPMessage(
        host=args.host,
        port=args.port,
        sender=args.sender,
        recipients=args.recipients,
        subject=args.subject,
        file_path=args.file_path,
        message_body=args.message_body,
        username=args.username,
        password=args.password,
    )

    client_cls = SSLSMTPWrapper if args.port == SMTP_SSL_PORT else SMTPClient

    with client_cls() as smtp_cli:
        smtp_cli.send_smtp_message(message)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--recipients", nargs="+")
    parser.add_argument("--sender")
    parser.add_argument("--subject")
    parser.add_argument("--file_path", default=None)
    parser.add_argument("--message_body", default="")

    # Auth
    parser.add_argument("--username")
    parser.add_argument("--password")
    args = parser.parse_args()

    send_single_smtp_message(args)
