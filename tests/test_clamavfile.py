import pytest
import sys
sys.path.append('../')
from cav.clamavfile import clamavfile


def test_fileinfo_daily_cdiff():
    clamobject = clamavfile('daily-25784.cdiff')
    assert clamobject.signatures() == 227432
    assert clamobject.filetype() == 'ClamAV-Diff'
    assert clamobject.version() == 25784
    assert clamobject.functionalitylevel() == 0
    assert clamobject.verifysignature() is True
    assert clamobject.signature() == 'XI79OQXq6AxB1+r4qIbST5g/4u1TpxFox8BrDyKMf9awFGAUcS9Ct76fOpgaUm+vxAUaCT/1pNZbVwspxi77ypjnGts2Olyq66L/qx0d3UIdc6SP55bRvldh2ru3ibdRHtVD68Aj+4ukF8EvYXwaUtCWvw3oJq26p0JhB+OE8mW5DQ5mMSNu8WvAWY7UYLwrwTsOvtFE2jqVYssRkIm0KXxWIgIOr9KySdjqR8U6GC3yjIPu982lX8IysjyrrQZRKuAt0cvdTPt7IIfPC9Vfl1ODV7E9Kdq+jskt0qep8KVbGH4RVJZNlDFuaa2xf42k2ihlK/9LNX2W8tkUxSc6ob'


def test_fileinfo_daily_cdiff_failed():
    clamobject = clamavfile('daily-25784-signature-fail.cdiff')
    assert clamobject.verifysignature() is False


def test_fileinfo_main_cdiff():
    clamobject = clamavfile('main-59.cdiff')
    assert clamobject.signatures() == 38430
    assert clamobject.filetype() == 'ClamAV-Diff'
    assert clamobject.version() == 59
    assert clamobject.headersize() == 21

"""
ClamAV-VDB:16 Apr 2020 07-58 -0400:25784:2267600:63:92baacd59fd26e6bcf03077add78d209:4Jp9JtGJY6nUk8JHDQQpQeBwlfXqskvhXL+vesDNqAeWCmjbudU+Hy/Nj4/BH2vl70c/R5B/VYY+eqqCQo6o7VGLqLJr/E+19gejqMp/iRcuHrtnLw6V/x3UjO3/qYVSlcJvAjtMI7FK32wjB+Sp8kaS/ZbfaFQp6trRQhisjqf:raynman:1587038339
ClamAV-Diff:50:4228877:
"""
def test_fileinfo_daily():
    clamobject = clamavfile('daily.cvd')
    assert clamobject.signatures() == 2267600
    assert clamobject.verifysignature() is True
    assert clamobject.headersize() == 512
    assert clamobject.footersize() == 0
    assert clamobject.filetype() == 'ClamAV-VDB'
    assert clamobject.version() == 25784
    assert clamobject.functionalitylevel() == 63
    assert clamobject.md5() == '92baacd59fd26e6bcf03077add78d209'
    assert clamobject.signature() == '4Jp9JtGJY6nUk8JHDQQpQeBwlfXqskvhXL+vesDNqAeWCmjbudU+Hy/Nj4/BH2vl70c/R5B/VYY+eqqCQo6o7VGLqLJr/E+19gejqMp/iRcuHrtnLw6V/x3UjO3/qYVSlcJvAjtMI7FK32wjB+Sp8kaS/ZbfaFQp6trRQhisjqf'
    assert clamobject.builder() == 'raynman'
    assert clamobject.createheader() == 'ClamAV-VDB:16 Apr 2020 07-58 -0400:25784:2267600:63:92baacd59fd26e6bcf03077add78d209:4Jp9JtGJY6nUk8JHDQQpQeBwlfXqskvhXL+vesDNqAeWCmjbudU+Hy/Nj4/BH2vl70c/R5B/VYY+eqqCQo6o7VGLqLJr/E+19gejqMp/iRcuHrtnLw6V/x3UjO3/qYVSlcJvAjtMI7FK32wjB+Sp8kaS/ZbfaFQp6trRQhisjqf:raynman:1587038339'

def test_fileinfo_daily_failed():
    clamobject = clamavfile('daily-signature-fail.cvd')
    assert clamobject.verifysignature() is False
