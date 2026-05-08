"""
logger.py - NetWatch structured logger
"""
from __future__ import annotations
import json, logging, os, sys
from datetime import datetime, timezone

_IS_TTY     = sys.stdout.isatty()
_LOG_LEVEL  = os.getenv("NETWATCH_LOG_LEVEL", "INFO").upper()
_LOG_FORMAT = os.getenv("NETWATCH_LOG_FORMAT", "auto")

_RESET  = "\033[0m"
_COLORS = {"DEBUG":"\033[36m","INFO":"\033[32m","WARNING":"\033[33m","ERROR":"\033[31m","CRITICAL":"\033[35m"}

class _Fmt(logging.Formatter):
    def format(self, record):
        use_json = (_LOG_FORMAT == "json") or (_LOG_FORMAT == "auto" and not _IS_TTY)
        msg = record.getMessage()
        fields = getattr(record, "fields", {})
        if use_json:
            payload = {"ts": datetime.now(timezone.utc).isoformat(), "level": record.levelname,
                       "logger": record.name, "msg": msg, **fields}
            if record.exc_info:
                payload["exc"] = self.formatException(record.exc_info)
            return json.dumps(payload, ensure_ascii=False, default=str)
        else:
            color = _COLORS.get(record.levelname, "")
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            extra = (" " + " ".join(f"{k}={v}" for k,v in fields.items())) if fields else ""
            exc = ("\n" + self.formatException(record.exc_info)) if record.exc_info else ""
            return f"{color}[{ts}] [{record.levelname:<8}] [{record.name}] {msg}{extra}{exc}{_RESET}"

def _setup_root():
    root = logging.getLogger("netwatch")
    if root.handlers:
        return root
    root.setLevel(getattr(logging, _LOG_LEVEL, logging.INFO))
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(_Fmt())
    root.addHandler(h)
    for noisy in ("werkzeug", "urllib3", "nmap"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    return root

_root = _setup_root()

class _Logger:
    """Wrapper that accepts keyword arguments as structured fields."""
    def __init__(self, name: str):
        self._logger = logging.getLogger(name)

    def _emit(self, level: int, msg: str, kwargs: dict):
        self._logger.log(level, msg, extra={"fields": kwargs})

    def info(self, msg: str, **kwargs):     self._emit(logging.INFO,     msg, kwargs)
    def debug(self, msg: str, **kwargs):    self._emit(logging.DEBUG,    msg, kwargs)
    def warn(self, msg: str, **kwargs):     self._emit(logging.WARNING,  msg, kwargs)
    def warning(self, msg: str, **kwargs):  self._emit(logging.WARNING,  msg, kwargs)
    def error(self, msg: str, **kwargs):    self._emit(logging.ERROR,    msg, kwargs)
    def critical(self, msg: str, **kwargs): self._emit(logging.CRITICAL, msg, kwargs)

def get_logger(name: str) -> _Logger:
    return _Logger(f"netwatch.{name}")

# Module-level shortcuts
_mod = _Logger("netwatch")
def info(msg: str, **kwargs):     _mod.info(msg, **kwargs)
def debug(msg: str, **kwargs):    _mod.debug(msg, **kwargs)
def warn(msg: str, **kwargs):     _mod.warn(msg, **kwargs)
def error(msg: str, **kwargs):    _mod.error(msg, **kwargs)
def critical(msg: str, **kwargs): _mod.critical(msg, **kwargs)
