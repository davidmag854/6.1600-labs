import typing as t
from dataclasses import dataclass
from enum import auto, unique, IntEnum

import common.crypto as crypto
import common.types as types
import common.codec as codec
import common.errors as errors

_T = t.TypeVar("_T", bound="LogData")


@dataclass
class LogData:
    pass

    def encode(self) -> bytes:
        return codec.encode([])

    @classmethod
    def decode(cls: _T) -> _T:
        return LogData()


@dataclass
class RegisterLogData(LogData):
    pass


@dataclass
class PutPhotoLogData(LogData):
    photo_id: int

    def encode(self):
        return codec.encode(
            [
                self.photo_id,
            ]
        )

    @classmethod
    def decode(cls: _T, data: bytes) -> _T:
        (photo_id,) = codec.decode(data)
        return cls(photo_id)


@unique
class OperationCode(IntEnum):
    REGISTER = auto()
    PUT_PHOTO = auto()
    DEVICE_INVITE = auto()
    DEVICE_ADDED = auto()
    DEVICE_REVOKED = auto()
    ALBUM_KEY = auto()


class LogEntry:
    def __init__(
        self,
        opcode: OperationCode,
        data: bytes,
        h,
        public_key,
        signature
    ) -> None:
        """
        Generates a new log entry with the given data
        """
        self.opcode = opcode.value
        self.data = data
        self.h = h
        self.pk = public_key
        self.signature = signature

    def __str__(self) -> str:
        return f"LogEntry(opcode={OperationCode(self.opcode)}\n" \
               f", data={self.data}\n" \
               f", hash={self.h})\n" \
               f"  pk={self.pk}\n" \
               f"  signa={self.signature}"

    def encode(self) -> bytes:
        """
        Encode this log entry and the contained data, and return
        a bytestring that represents the whole thing.
        """
        result = codec.encode(
            [
                self.opcode,
                self.data,
                self.h,
                self.pk,
                self.signature
            ]
        )
        return result

    @staticmethod
    def decode(data: bytes) -> "LogEntry":
        """
        Decode this log entry and the contained data
        """
        opcode_int, log_data, h, pk, sign = codec.decode(data)
        opcode = OperationCode(opcode_int)
        return LogEntry(opcode, log_data, h, pk, sign)

    def data_hash(self) -> bytes:
        return crypto.data_hash(self.encode())

