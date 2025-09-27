from enum import StrEnum
import re

email_validation_regex = re.compile(r"^(?P<addr>[A-Za-z0-9._%+-]+)@(?P<host>[A-Za-z0-9.-]+.[a-zA-Z]{2,})$")

SMTP_PORT = 25
SMTP_SSL_PORT = 465
CRLF = "\r\n"
bCRLF = b"\r\n"
SP = " "
bSP = b" "
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 5454
DEFAULT_BUFFER = 4096

class SmtpReplyCode(StrEnum):
    # 2xx Positive Completion
    SYSTEM_STATUS = "211 System status, or system help reply"
    HELP_MESSAGE = "214 Help message"
    SERVICE_READY = "220 Service ready"
    SERVICE_CLOSING = "221 Service closing transmission channel"
    OK = "250 Requested mail action okay, completed"
    USER_NOT_LOCAL = "251 User not local; will forward"
    CANNOT_VRFY_USER = "252 Cannot VRFY user, but will accept message"

    # 3xx Positive Intermediate
    START_MAIL_INPUT = "354 Start mail input; end with <CRLF>.<CRLF>"

    # 4xx Transient Negative Completion
    SERVICE_NOT_AVAILABLE = "421 Service not available, closing transmission channel"
    MAILBOX_UNAVAILABLE = "450 Requested mail action not taken: mailbox unavailable"
    LOCAL_ERROR = "451 Requested action aborted: local error in processing"
    INSUFFICIENT_STORAGE = "452 Requested action not taken: insufficient system storage"

    # 5xx Permanent Negative Completion
    SYNTAX_ERROR = "500 Syntax error, command unrecognized"
    ARGUMENT_SYNTAX_ERROR = "501 Syntax error in parameters or arguments"
    COMMAND_NOT_IMPLEMENTED = "502 Command not implemented"
    BAD_SEQUENCE = "503 Bad sequence of commands"
    PARAMETER_NOT_IMPLEMENTED = "504 Command parameter not implemented"
    MUST_STARTTLS = "530 Authentication required"
    MAILBOX_UNAVAILABLE_PERM = "550 Requested action not taken: mailbox unavailable"
    USER_NOT_LOCAL_PERM = "551 User not local; please try <forward-path>"
    EXCEEDED_STORAGE = "552 Requested mail action aborted: exceeded storage allocation"
    MAILBOX_NAME_NOT_ALLOWED = "553 Requested action not taken: mailbox name not allowed"
    TRANSACTION_FAILED = "554 Transaction failed"

    @classmethod
    def from_code(cls, code: int) -> "SmtpReplyCode | None":
        for member in cls:
            if member.code == code:
                return member
        return None

    @property
    def code(self) -> int:
        return int(self.value.split()[0])

    @property
    def reason(self) -> str:
        return " ".join(self.value.split()[1:])

