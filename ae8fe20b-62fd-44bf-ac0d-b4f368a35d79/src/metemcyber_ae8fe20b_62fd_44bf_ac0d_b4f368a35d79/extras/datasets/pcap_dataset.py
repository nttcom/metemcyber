from copy import deepcopy
from pathlib import PurePosixPath
from typing import Any, Dict, List, Tuple

import fsspec
import dpkt
#import scapy

from kedro.io.core import (
    AbstractDataSet,
    DataSetError,
    get_filepath_str,
    get_protocol_and_path,
)


class PcapDataSet(AbstractDataSet):
    def __init__(self, filepath: str):
        """Creates a new instance of scapy.plist.PacketList to load / save image data for given filepath.

        Args:
            filepath: The location of the image file to load / save data.
        """        
        protocol, path = get_protocol_and_path(filepath)
        self._protocol = protocol
        self._filepath = PurePosixPath(path)
        self._fs = fsspec.filesystem(self._protocol)

    #def _load(self) -> scapy.plist.PacketList:
    def _load(self) -> List[Tuple[float, bytes]]:
        """Loads data from pcap file.

        Returns:
            Parse result of a pcap as a scapy.plist.PacketList.
        """
        #load_path = get_filepath_str(self._get_load_path(), self._protocol)
        load_path = self._filepath

        packets = []
        with self._fs.open(load_path) as f:
            pcr = dpkt.pcap.Reader(f)
            for ts, buf in pcr:
                packets.append((ts, buf))
        return packets
        #return scapy.rdpcap(load_path)

    def _save(self) -> None:
        pass

    def _describe(self) -> Dict[str, Any]:
        return dict(filepath=self._filepath, protocol=self._protocol)

"""
class PcapDataSet(AbstractVersionedDataSet):
    def __init__(
            self,
            filepath: str,
            load_args: Dict[str, Any] = None,
            save_args: Dict[str, Any] = None,
            version: Version = None,
            credentials: Dict[str, Any] = None,
            fs_args: Dict[str, Any] = None,
        ) -> None:

        _fs_args = deepcopy(fs_args) or {}
        _fs_open_args_load = _fs_args.pop("open_args_load", {})
        _fs_open_args_save = _fs_args.pop("open_args_save", {})
        _credentials = deepcopy(credentials) or {}

        self._load_args = deepcopy(self.DEFAULT_LOAD_ARGS)
        if load_args is not None:
            self._load_args.update(load_args)
        self._save_args = deepcopy(self.DEFAULT_SAVE_ARGS)
        if save_args is not None:
            self._save_args.update(save_args)

    def _describe(self) -> Dict[str, Any]:
        return dict(
            filepath=self._filepath,
            protocol=self._protocol,
            load_args=self._load_args,
            save_args=self._save_args,
            version=self._version,
        )

    def _load(self) -> scapy.plist.PacketList:
        load_path = get_filepath_str(self._get_load_path(), self._protocol)

        return scapy.rdpcap(load_path)

    def _save(self, pkts: scapy.plist.PacketList) -> None:
        save_path = get_filepath_str(self._get_save_path(), self._protocol)
        scapy.wrpcap(save_path, pkts)
"""