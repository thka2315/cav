import pytest
import sys
sys.path.append('../')
from cav.clamavfile import clamavfile


def test_fileinfo_daily_cdiff():
    clamobject = clamavfile('daily-25784.cdiff')
    assert clamobject.signatures() == 227432
    assert clamobject.filetype() == 'ClamAV-Diff'
    assert clamobject.version() == 25784
    assert clamobject.verifysignature() is True


def test_fileinfo_daily_cdiff_failed():
    clamobject = clamavfile('daily-25784-signature-fail.cdiff')
    assert clamobject.verifysignature() is False


def test_fileinfo_main_cdiff():
    clamobject = clamavfile('main-59.cdiff')
    assert clamobject.signatures() == 38430
    assert clamobject.filetype() == 'ClamAV-Diff'
    assert clamobject.version() == 59


def test_fileinfo_daily():
    clamobject = clamavfile('daily.cvd')
    assert clamobject.builder() == 'raynman'
    assert clamobject.signatures() == 2267600
    assert clamobject.verifysignature() is True


def test_fileinfo_daily_failed():
    clamobject = clamavfile('daily-signature-fail.cvd')
    assert clamobject.verifysignature() is False
