#!/usr/bin/python3

# Handle ClamAV files
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

import os
import re
import hashlib
from typing import List, Dict, Union, Any


class clamavfile:
    'Extract metadata from ClamAV files'
    def __init__(self, clamfile: str):
        if not os.path.exists(clamfile):
            raise FileNotFoundError(clamfile)
        self.filename = clamfile
        self.fileinfo = self.fileinformation()
        self.magicheader = self.readmagicheader()
        self.header = self.readheader()
        self.nstr = 118640995551645342603070001658453189751527774412027743746599405743243142607464144767361060640655844749760788890022283424922762488917565551002467771109669598189410434699034532232228621591089508178591428456220796841621637175567590476666928698770143328137383952820383197532047771780196576957695822641224262693037
        self.estr = 100001027
        self.pss_nstr = 14783905874077467090262228516557917570254599638376203532031989214105552847269687489771975792123442185817287694951949800908791527542017115600501303394778618535864845235700041590056318230102449612217458549016089313306591388590790796515819654102320725712300822356348724011232654837503241736177907784198700834440681124727060540035754699658105895050096576226753008596881698828185652424901921668758326578462003247906470982092298106789657211905488986281078346361469524484829559560886227198091995498440676639639830463593211386055065360288422394053998134458623712540683294034953818412458362198117811990006021989844180721010947
        self.pss_estr = 100002053
        self.pss_nbits = 2048

    def datatofile(self, destinationfile: str) -> None:
        with open(self.filename, 'rb') as clamfile:
            if self.magicheader == 'ClamAV-VDB':
                clamfile.read(self.headersize())
                with open(destinationfile, 'wb') as extractfile:
                    extractfile.write(clamfile.read())
            if self.magicheader == 'ClamAV-Diff':
                clamfile.read(self.headersize())
                with open(destinationfile, 'wb') as extractfile:
                    extractfile.write(clamfile.read(self.datasize()))

    def _chardecode(self, onechar: str) -> int:
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/'
        for i in range(0, 64):
            if chars[i] == onechar:
                return i

        return -1

    def _decodesignature(self, signaturestring, e, n) -> str:
        counter = 0
        added = 0
        for onechar in signaturestring:
            decoded = self._chardecode(onechar)
    #        /* c = a * 2**d */
            prod = decoded * pow(2, 6 * counter)
            added = prod + added
            counter += 1
        # /* plain = cipher^e mod n */
        plainmod = pow(added, e, n)

        return format(plainmod, "02x")

    def _stringtolist(self, instr: str) -> List[str]:
        return [(instr[i:i+2]) for i in range(0, len(instr), 2)]

    def verifysignature(self) -> bool:
        md5object = hashlib.md5()
        sha256object = hashlib.sha256()
        if self.signature == '':
            return False
        with open(self.filename, 'rb') as clamfile:
            if self.magicheader == 'ClamAV-VDB':
                clamfile.read(512)
                for chunk in iter(lambda: clamfile.read(8192), b''):
                    md5object.update(chunk)
                decryptedhash = self._decodesignature(self.signature(),
                                                      self.estr,
                                                      self.nstr)
                decryptedhash = decryptedhash.zfill(32)
                if decryptedhash == md5object.hexdigest():
                    return True
            if self.magicheader == 'ClamAV-Diff':
                decryptedsignaturestring = self._decodesignature(self.signature(),
                                                       self.pss_estr,
                                                       self.pss_nstr)
                decryptedsignaturestring = decryptedsignaturestring.zfill(512)
                decryptedsignaturelist = self._stringtolist(decryptedsignaturestring)
                bytestoread = self.fileinfo.st_size - self.footersize()
                data = clamfile.read(bytestoread)
                sha256object.update(data)
                decryptedbytelist = bytearray()
                for i in range(0, len(decryptedsignaturelist)):
                    decryptedbytelist.append(int(decryptedsignaturelist[i],
                                                 16))

                # MASK
                mask = bytearray()
                for i in range(0, 223):
                    mask.append(decryptedbytelist[i])
                digest2 = bytearray()
                for i in range(223, 255):
                    digest2.append(decryptedbytelist[i])

                datastr = str()
                for num in range(0, 7):
                    testhash = hashlib.sha256()
                    testhash.update(digest2)
                    testhash.update(b'\x00\x00\x00')
                    # testhash.update(b'\x00')
                    # testhash.update(b'\x00')
                    testhash.update(bytes(chr(num), 'ascii'))
                    datastr += testhash.hexdigest()
                datalist = self._stringtolist(datastr)
                data = bytearray()
                xordata = bytearray()
                for i in range(0, 223):
                    data.append(int(datalist[i], 16))
                for i in range(0, 223):
                    xordata.append(data[i] ^ mask[i])
                xordata[0] &= (0xff >> 1)
                salt = 0
                for i in range(0, 223):
                    if xordata[i] == 0x01:
                        salt = i + 1
                        break
                final = bytearray()
                final.append(0x00)
                final.append(0x00)
                final.append(0x00)
                final.append(0x00)
                final.append(0x00)
                final.append(0x00)
                final.append(0x00)
                final.append(0x00)
                final.extend(sha256object.digest())
                for i in range(salt, salt + 32):
                    final.append(xordata[i])
                finalhash = hashlib.sha256()
                finalhash.update(final)
                digest2str = "".join(format(x, '02x') for x in digest2)
                if finalhash.hexdigest() == digest2str:
                    return True

        return False

    def fileinformation(self) -> os.stat_result:
        # print(os.stat(self.filename))
        return os.stat(self.filename)

    def readmagicheader(self) -> str:
        'Read 12 bytes from file and output header'
        with open(self.filename, 'rb') as clamfile:
            filedata = clamfile.read(12)
            so = re.split(b':', filedata, 1)

        return so[0].decode('utf-8')

    def readheader(self) -> Dict[str, Any]:
        """
        Get the magic header bytes from the file to see what kind of
        ClamAV file it is

        ClamAV-VDB:19 Sep 2019 12-12 -0400:331:94:63:07b42b8527b2c82d7236bbc
        32458e245:i4NE7BC0pb7xpS39DmgbDXcQl9ka5121HLSuo0mIKvXvZjFb9z7wgU6oOMw
        iRpM8vucAcmFGCemGSemwPQyGs1Rzro5ufqo1Kq4LJOvfJKhLMo94XbGwjannyvYWpUPR
        8udGcUjn/YHJ3rCgGaANSYFRbTgkbDwsuLhGatD7tJf:anvilleg:1568909553
        ClamAV-Diff:50:4228877:
        """
        header: Dict[str, Union[str, int]] = dict()
        if self.magicheader == 'ClamAV-VDB':
            bytestoread = 512
            headersize = 512
            footersize = 0
            with open(self.filename, 'rb') as clamfile:
                filedata = clamfile.read(bytestoread)
            so = re.split(b':', filedata, 8)
            header['headersize'] = headersize
            header['footersize'] = footersize
            header['filetype'] = so[0].decode('utf-8')
            header['signaturedate'] = so[1].decode('utf-8')
            header['version'] = int(so[2].decode('utf-8'))
            header['signatures'] = int(so[3].decode('utf-8'))
            header['functionalitylevel'] = int(so[4].decode('utf-8'))
            header['md5'] = so[5].decode('utf-8')
            header['signature'] = so[6].decode('utf-8')
            header['builder'] = so[7].decode('utf-8')
            header['epoch'] = int(so[8].decode('utf-8').rstrip())
            header['datasize'] = self.fileinfo.st_size - headersize - footersize
        if self.magicheader == 'ClamAV-Diff':
            with open(self.filename, 'rb') as clamfile:
                headerdata = clamfile.read(40)
                clamfile.seek(-350, 2)
                signaturedata = clamfile.read()
            so = re.split(b':', headerdata, 3)
            header['filetype'] = so[0].decode('utf-8')
            header['version'] = int(so[1].decode('utf-8'))
            header['signatures'] = int(so[2].decode('utf-8'))
            header['headersize'] = int(len(str(header['filetype'])) + \
                len(str(header['version'])) + \
                len(str(header['signatures'])) + \
                3)
            signatureposition = -1
            for i in range(0, 349):
                if not self._signaturecharacter(signaturedata[i]):
                    signatureposition = -1
                if signaturedata[i] == 58:
                    signatureposition = i
            if signatureposition != -1:
                header['footersize'] = 350 - signatureposition
                header['signature'] = signaturedata[signatureposition + 1:].decode('utf-8')

            header['datasize'] = self.fileinfo.st_size - int(header['headersize']) - int(header['footersize'])

        return header

    def headersize(self) -> int:
        """
            Returns header size
        """
        if 'headersize' in self.header:
            return self.header['headersize']

        return 0

    def footersize(self) -> int:
        """
            Returns footer size
        """
        if 'footersize' in self.header:
            return self.header['footersize']

        return 0

    def filetype(self) -> str:
        """
            Returns ClamAV-VDB or ClamAV-Diff
        """
        if 'filetype' in self.header:
            return self.header['filetype']

        return 'unknown'

    def version(self) -> int:
        """
            Returns version of signature
        """
        if 'version' in self.header:
            return self.header['version']

        return 0

    def signatures(self) -> int:
        """
            Returns number of signatures in the file
        """
        if 'signatures' in self.header:
            return self.header['signatures']

        return 0

    def signaturedate(self) -> str:
        """
            Returns the date when the signature was generated
        """
        if 'signaturedate' in self.header:
            return self.header['signaturedate']

        return '01 Jan 1970 01-01 -0400'

    def functionalitylevel(self) -> int:
        """
            Returns the functionality level of the signatures
        """
        if 'functionalitylevel' in self.header:
            return self.header['functionalitylevel']

        return 0

    def signature(self) -> int:
        """
            Returns the signature of the signatures
        """
        if 'signature' in self.header:
            return self.header['signature']

        return 0

    def builder(self) -> int:
        """
            Returns the builder of the signatures
        """
        if 'builder' in self.header:
            return self.header['builder']

        return 0

    def epoch(self) -> int:
        """
            Returns the epoch time when the signatures was created
        """
        if 'epoch' in self.header:
            return self.header['epoch']

        return 0

    def datasize(self) -> int:
        """
            Returns the size of the signatures
        """
        if 'datasize' in self.header:
            return self.header['datasize']

        return 0

    def _signaturecharacter(self, onechar: int) -> bool:
        if onechar > 64 and onechar < 91:
            return True
        if onechar > 96 and onechar < 123:
            return True
        if onechar > 46 and onechar < 59:
            return True
        if onechar == 43:
            return True

        return False

    # def _filetype(self) -> str:
    #     """
    #     Return filetype
    #     ClamAV-Diff:50:4228877:
    #     ClamAV-VDB:22 Mar 2020 09-14 -0400:
    #         25759:2234135:63:098e56e33ae0db8b9d3b536ee80fb66e
    #     """
    #     filetype = self.magicheader
    #     if filetype == 'ClamAV-VDB':
    #         self.clamavfile = True
    #         return filetype
    #     elif filetype == 'ClamAV-Diff':
    #         self.clamavfile = True
    #         return filetype
    #     else:
    #         return 'Unknown'
