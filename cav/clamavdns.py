#!/usr/bin/python3

# ClamAV DNS TXT record
# Copyright 2021 Thomas Karlsson
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import DNS
import json
from typing import Dict, Union


class clamavdns:
    """
    "0.102.2:59:25755:1584556141:1:63:49191:331"
    """
    def __init__(self):
        self._clamversion: str = ''
        self._mainversion: int = 0
        self._dailyversion: int = 0
        self._signaturedate: int = 0
        self._versionwarning: int = 0
        self._functionalitylevel: int = 0
        self._safebrowsingversion: int = 0
        self._bytecodeversion: int = 0
        self.clamdata: Dict[str, Union[str, int]] = dict()

    def _datadict(self) -> None:
        self.clamdata['clamversion'] = self._clamversion
        self.clamdata['mainversion'] = self._mainversion
        self.clamdata['dailyversion'] = self._dailyversion
        self.clamdata['signaturedate'] = self._signaturedate
        self.clamdata['versionwarning'] = self._versionwarning
        self.clamdata['functionalitylevel'] = self._functionalitylevel
        self.clamdata['safebrowsingversion'] = self._safebrowsingversion
        self.clamdata['bytecodeversion'] = self._bytecodeversion

        return None

    def dnsquery(self) -> None:
        clamavquery = DNS.DnsRequest("current.cvd.clamav.net",
                                     qtype="TXT", protocol='udp')
        res = clamavquery.req()
        # Get first answer
        signaturedata = res.answers[0]['data'][0].split(b':')
        self._clamversion = signaturedata[0].decode()
        self._mainversion = int(signaturedata[1].decode())
        self._dailyversion = int(signaturedata[2].decode())
        self._signaturedate = int(signaturedata[3].decode())
        self._versionwarning = int(signaturedata[4].decode())
        self._functionalitylevel = int(signaturedata[5].decode())
        self._safebrowsingversion = int(signaturedata[6].decode())
        self._bytecodeversion = int(signaturedata[7].decode())

        self._datadict()

        return None

    def text(self) -> str:
        """
            Returns the same data as the DNS text
        """
        dnsstring = str()
        dnsstring = "{}:{}:{}:{}:".format(self.clamversion(),
                                          self.mainversion(),
                                          self.dailyversion(),
                                          self.signaturedate())
        if self.versionwarning():
            dnsstring += "1:"
        else:
            dnsstring += "0:"

        dnsstring += "{}:{}:{}".format(self.functionalitylevel(),
                                       self.safebrowsingversion(),
                                       self.bytecodeversion())

        return dnsstring

    def json(self, pretty: bool = True) -> str:
        """
            Returns a json string of DNS data
        """

        if pretty:
            return json.dumps(self.clamdata, indent='  ')
        else:
            return json.dumps(self.clamdata)

    def clamversion(self) -> str:
        """
            Returns ClamAV version from DNS
        """
        return self._clamversion

    def mainversion(self) -> int:
        """
            Returns main version of signature from DNS
        """
        return self._mainversion

    def dailyversion(self) -> int:
        """
            Returns daily version of signature from DNS
        """
        return self._dailyversion

    def signaturedate(self) -> int:
        """
            Returns signature date of signature from DNS
        """
        return self._signaturedate

    def versionwarning(self) -> bool:
        """
            Returns True if the warning flag is 1, else False (0)
        """
        if self._versionwarning == "1":
            return True
        else:
            return False

    def functionalitylevel(self) -> int:
        """
            Returns the funcionality level of signature from DNS
        """
        return self._functionalitylevel

    def safebrowsingversion(self) -> int:
        """
            Returns the safe browsing version of signature from DNS
        """
        return self._safebrowsingversion

    def bytecodeversion(self) -> int:
        """
            Returns the byte code version of signature from DNS
        """
        return self._bytecodeversion

    def savestatefile(self, statefilename: str = 'clamav.state') -> bool:
        'Save retrieved dns data as json to file'
        with open(statefilename, 'w') as statefile:
            print(json.dumps(self.clamdata, indent='  '), file=statefile)

        return True

    def loadstatefile(self, statefilename: str = 'clamav.state') -> bool:
        with open(statefilename, 'r') as statefile:
            self.datadict = json.load(statefile)
            self._clamversion = self.datadict['clamversion']
            self._mainversion = self.datadict['mainversion']
            self._dailyversion = self.datadict['dailyversion']
            self._signaturedate = self.datadict['signaturedate']
            self._versionwarning = self.datadict['versionwarning']
            self._functionalitylevel = self.datadict['functionalitylevel']
            self._safebrowsingversion = self.datadict['safebrowsingversion']
            self._bytecodeversion = self.datadict['bytecodeversion']
            self._datadict()

        return True
