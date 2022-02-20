import asyncio
from collections import defaultdict
from typing import Any, Callable, Dict

from xml.etree import ElementTree as ET

from networkmapper.utils import async_for
from networkmapper.exceptions import NmapError

nmap_path = ""  # TODO (Shubham) Make this configurable
cmnd_args = "-oX - -Pn --script ssl-cert".split(" ")
_stdout: Callable[[], Dict[str, Dict]] = lambda: {
    "state": dict(),
    "service": dict(),
    "script": dict(),
    "scriptDict": dict(),
}


async def cleandict(badd: Dict[str, Any]) -> Dict[str, Any]:
    """Clean keys and values by removing extra spaces & tabs

    Args:
        badd (Dict[str, Any]): bad dictionary

    Returns:
        Dict[str, Any]: cleaned dictionary
    """
    cleaned: Dict[str, Any] = dict()

    async for key, value in async_for(badd.items()):
        ckey = key.strip(" \t").strip(" ")
        if isinstance(value, dict):
            cleaned[ckey] = await cleandict(value)
        elif isinstance(value, list):
            cleaned[ckey] = list()
            async for val in async_for(value):
                cleaned[ckey].append(await cleandict(val))
        else:
            cleaned[ckey] = value.strip(" \t").strip(" ")

    return cleaned


class _SSLCertXMLTarget:
    ports: Dict[str, Dict] = defaultdict(_stdout)
    lpkey: str = ""

    def start(self, tag: str, attrib: Dict):
        if tag.lower() in ("port",):
            _id = attrib.get("portid", "NA")
            protocol = attrib.get("protocol", "NA")
            self.lpkey = f"{_id}/{protocol}"
        elif tag.lower() in ("state", "service", "script") and self.lpkey:
            self.ports[self.lpkey][tag.lower()].update(attrib)

    def end(self, tag: str):
        if tag.lower() in ("port",):
            self.lpkey = ""

    def close(self):
        return {
            port: val
            for port, val in self.ports.items()
            if val.get("script", None) or val.get("state", dict()).get("state", "").lower() == "open"
        }

    def data(self, data):
        pass


class Nmap:
    def __init__(self, ip: str) -> None:
        self.__parser = ET.XMLParser(target=_SSLCertXMLTarget())
        self.__raw: Dict[str, Any] = dict()
        self._ip = ip

    @property
    def raw(self):
        return self.__raw

    @staticmethod
    async def fromstring(string: str) -> Dict[str, Any]:
        """Form dictionary from string based using `:`,`\\`,`=`
        and `,` as separators.

        Args:
            string (str): string data of `ssl-cert` script

        Returns:
            Dict[str, Any]: converted dictionary
        """
        sslcertdict: Dict[str, Any] = dict()

        if ":" in string:
            key, value = string.split(":", 1)
            if "=" in value:
                sslcertdict[key] = await Nmap.fromstring(value)
            elif "," in value:
                sslcertdict[key] = list()
                async for key_val in async_for(value.split(",")):
                    sslcertdict[key].append(await Nmap.fromstring(key_val))
            elif ":" in value:
                sslcertdict[key] = await Nmap.fromstring(value)
            else:
                sslcertdict[key] = value
        elif "=" in string:
            if "/" in string:
                nested_sslcert = dict()
                async for key_val in async_for(string.split("/")):
                    nested_sslcert.update(await Nmap.fromstring(key_val))
                return nested_sslcert
            else:
                key, value = string.split("=", 1)
                sslcertdict[key] = value

        return sslcertdict

    @staticmethod
    async def outputdict(data: str) -> Dict[str, Any]:
        """Process output string convert into dictionary

        Args:
            data (str): string value of output key

        Returns:
            Dict[str, Any]: clean converted dictionary
        """
        _outdict = dict()

        async for item in async_for(data.split("\n")):
            _outdict.update(await Nmap.fromstring(item))

        return await cleandict(_outdict)

    async def parse_attrib(self, attrib: Dict[str, Any]) -> Dict[str, Any]:
        """Parse attributes present for script `ssl-cert`

        Args:
            attrib (Dict[str, Any]): attributes dictionary from xml

        Returns:
            Dict[str, Any]: `ssl-cert` script data
        """

        if output := attrib.get("output"):
            return await self.outputdict(output)
        return dict()

    async def parse(self, output: bytes) -> None:
        """Parse output returned from nmap subprocess

        Args:
            output (bytes): nmap std output
        """
        try:
            self.__parser.feed(output)
        except Exception as xerr:
            pass  # TODO (Shubham): Complete this

        self.__raw = self.__parser.close()

        async for _, data in async_for(self.__raw.items()):
            self.__raw.update({"scriptDict": await self.parse_attrib(data.get("script", dict()))})

    async def nmap(self, timeout: int = 120) -> None:
        """Spawn nmap subprocess and parse output

        Args:
            timeout (int, optional): timeout for suprocess. Default to 120.
        """

        cmnd = cmnd_args + [f"{self._ip}"]
        subp = await asyncio.create_subprocess_exec(
            nmap_path, *cmnd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )  # TODO (Shubham): Don't do DEVNULL .. return error back

        try:
            stdout, stderr = await asyncio.wait_for(subp.communicate(), timeout=timeout)
            if stderr is None:
                await self.parse(stdout)
            else:
                raise NmapError(stderr)
        except asyncio.TimeoutError:
            subp.kill()
        except NmapError as nerr:
            pass  # TODO (Shubham): Complete this
