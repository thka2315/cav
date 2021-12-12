import sys
sys.path.append('../')
from cav.clamavdns import clamavdns

# 0.102.2:59:25755:1584556141:1:63:49191:331
def test_dns():
    clamdns = clamavdns()
    clamdns._clamversion = "0.102.2"
    clamdns._mainversion = "59"
    clamdns._dailyversion = "25755"
    clamdns._signaturedate = "1584556141"
    clamdns._versionwarning = "1"
    clamdns._functionalitylevel = "63"
    clamdns._safebrowsingversion = "49191"
    clamdns._bytecodeversion = "331"
    clamdns._datadict()

    assert clamdns.clamversion() == "0.102.2"
    assert clamdns.mainversion() == "59"
    assert clamdns.dailyversion() == "25755"
    assert clamdns.signaturedate() == "1584556141"
    assert clamdns.versionwarning() == True
    assert clamdns.functionalitylevel() == "63"
    assert clamdns.safebrowsingversion() == "49191"
    assert clamdns.bytecodeversion() == "331"
    assert clamdns.text() == "0.102.2:59:25755:1584556141:1:63:49191:331"
    assert clamdns.json(pretty = False) == '{"clamversion": "0.102.2", "mainversion": "59", "dailyversion": "25755", "signaturedate": "1584556141", "versionwarning": "1", "functionalitylevel": "63", "safebrowsingversion": "49191", "bytecodeversion": "331"}'
    assert clamdns.savestatefile() == True
    saveddns = clamavdns()
    assert saveddns.loadstatefile() == True
    assert saveddns.text() == "0.102.2:59:25755:1584556141:1:63:49191:331"
    assert saveddns.json(pretty = False) == '{"clamversion": "0.102.2", "mainversion": "59", "dailyversion": "25755", "signaturedate": "1584556141", "versionwarning": "1", "functionalitylevel": "63", "safebrowsingversion": "49191", "bytecodeversion": "331"}'
