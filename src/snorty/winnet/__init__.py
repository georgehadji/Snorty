"""Windows adapter for the PC's TCP and UDP connection tables (ctypes over iphlpapi)."""

from snorty.winnet.lookup import WinConnectionLookup

__all__ = ["WinConnectionLookup"]
