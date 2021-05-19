from pathlib import PurePosixPath
from typing import Any, Dict, List, Tuple

import dpkt
import fsspec
from kedro.io.core import AbstractDataSet, get_protocol_and_path


class PcapDataSet(AbstractDataSet):
    def __init__(self, filepath: str):
        """Creates a new instance of scapy.plist.PacketList to load /
           save image data for given filepath.

        Args:
            filepath: The location of the image file to load / save data.
        """
        protocol, path = get_protocol_and_path(filepath)
        self._protocol = protocol
        self._filepath = PurePosixPath(path)
        self._fs = fsspec.filesystem(self._protocol)

    def _load(self) -> List[Tuple[float, bytes]]:
        """Loads data from pcap file.

        Returns:
            Parse result of a pcap as a scapy.plist.PacketList.
        """
        load_path = self._filepath

        packets = []
        with self._fs.open(load_path) as f:
            pcr = dpkt.pcap.Reader(f)
            for ts, buf in pcr:
                packets.append((ts, buf))
        return packets

    def _save(self) -> None:
        pass

    def _describe(self) -> Dict[str, Any]:
        return dict(filepath=self._filepath, protocol=self._protocol)
