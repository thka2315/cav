#!/usr/bin/python3

# ClamAV DNS TXT record
# Copyright 2020 Thomas Karlsson
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


class clamavdns:
    """
    "0.102.2:59:25755:1584556141:1:63:49191:331"
    """
    def __init__(self):
        self.clamversion = ''
        self.mainversion = 0
        self.dailyversion = 0
        self.signaturedate = 0
        self.versionwarning = 0
        self.functionalitylevel = 0
        self.safebrowsingversion = 0
        self.bytecodeversion = 0
        self.datadict = dict()

    def getonline(self):
        clamavquery = DNS.DnsRequest("current.cvd.clamav.net",
                                     qtype="TXT", protocol='udp')
        res = clamavquery.req()
        # Get first answer
        signaturedata = res.answers[0]['data'][0].split(b':')
        self.clamversion = signaturedata[0].decode()
        self.mainversion = int(signaturedata[1].decode())
        self.dailyversion = int(signaturedata[2].decode())
        self.signaturedate = int(signaturedata[3].decode())
        self.versionwarning = int(signaturedata[4].decode())
        self.functionalitylevel = int(signaturedata[5].decode())
        self.safebrowsingversion = int(signaturedata[6].decode())
        self.bytecodeversion = int(signaturedata[7].decode())

        self.datadict['clamversion'] = self.clamversion
        self.datadict['mainversion'] = self.mainversion
        self.datadict['dailyversion'] = self.dailyversion
        self.datadict['signaturedate'] = self.signaturedate
        self.datadict['versionwarning'] = self.versionwarning
        self.datadict['functionalitylevel'] = self.functionalitylevel
        self.datadict['safebrowsingversion'] = self.safebrowsingversion
        self.datadict['bytecodeversion'] = self.bytecodeversion

    def savestatefile(self) -> bool:
        'Save retrieved dns data as json to file'
        with open('clamav.state', 'w') as statefile:
            print(json.dumps(self.datadict, indent='  '), file=statefile)

        return True

    def loadstatefile(self) -> bool:
        with open('clamav.state', 'r') as statefile:
            self.datadict = json.load(statefile)
            self.mainversion = self.datadict['mainversion']
            self.dailyversion = self.datadict['dailyversion']
            self.signaturedate = self.datadict['signaturedate']
            self.versionwarning = self.datadict['versionwarning']
            self.functionalitylevel = self.datadict['functionalitylevel']
            self.safebrowsingversion = self.datadict['safebrowsingversion']
            self.bytecodeversion = self.datadict['bytecodeversion']

        return True

    def json(self):
        return json.dumps(self.datadict, indent='  ')
