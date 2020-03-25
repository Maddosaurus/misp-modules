"""Unit Test module for the VMRay Enrichment module"""
import json
from unittest import mock

from misp_modules.modules.expansion import vmray_submit


def test_handler_set_flags(monkeypatch):
    submit_mock = mock.Mock()
    monkeypatch.setattr(vmray_submit, "vmraySubmit", submit_mock)
    mock_q = {
        "attachment": "dGVzdHN0cmluZw==",
        "data": "dGVzdHN0cmluZw==",
        "config": {
            "apikey": "1234",
            "url": "http://localhost",
            "shareable": "True",
            "do_not_reanalyze": "True",
            "do_not_include_vmrayjobids": "True"
        }
    }

    vmray_submit.handler(json.dumps(mock_q))

    submit_mock_call_args = submit_mock.call_args[0][1]
    assert submit_mock_call_args["reanalyze"] is False
    assert submit_mock_call_args["shareable"] is True


def test_handler_set_illegal_setting(monkeypatch):
    submit_mock = mock.Mock()
    monkeypatch.setattr(vmray_submit, "vmraySubmit", submit_mock)
    mock_q = {
        "attachment": "dGVzdHN0cmluZw==",
        "data": "dGVzdHN0cmluZw==",
        "config": {
            "apikey": "1234",
            "url": "http://localhost",
            "shareable": "True",
            "do_not_reanalyze": "True",
            "do_not_include_vmrayjobids": "ILLEGAL_SETTING"
        }
    }

    result = vmray_submit.handler(json.dumps(mock_q))

    assert result == {'error': 'Error while processing settings. Please double-check your values.'}


def test_handler_capitalize_strings(monkeypatch):
    submit_mock = mock.Mock()
    monkeypatch.setattr(vmray_submit, "vmraySubmit", submit_mock)
    mock_q = {
        "attachment": "dGVzdHN0cmluZw==",
        "data": "dGVzdHN0cmluZw==",
        "config": {
            "apikey": "1234",
            "url": "http://localhost",
            "shareable": "true",
            "do_not_reanalyze": "trUe",
            "do_not_include_vmrayjobids": "False"
        }
    }

    vmray_submit.handler(json.dumps(mock_q))

    submit_mock_call_args = submit_mock.call_args[0][1]
    assert submit_mock_call_args["reanalyze"] is False
    assert submit_mock_call_args["shareable"] is True


def test_successful_submission(monkeypatch, requests_mock):
    monkeypatch.setattr(vmray_submit, "vmrayProcess", mock.Mock())
    requests_mock.post("http://localhost/rest/sample/submit", json={"data": {"errors": []}}, status_code=200)
    mock_q = {
        "attachment": "dGVzdHN0cmluZw==",
        "data": "dGVzdHN0cmluZw==",
        "config": {
            "apikey": "1234",
            "url": "http://localhost",
            "shareable": "true",
            "do_not_reanalyze": "trUe",
            "do_not_include_vmrayjobids": "False"
        }
    }

    result = vmray_submit.handler(json.dumps(mock_q))

    assert isinstance(result, mock.Mock)


def test_vmrayProcess_new_submission():
    json_data = {
        "errors": [],
        "jobs": [{
            "job_configuration_name": "config_name",
            "job_id": 4242,
            "job_vm_name": "vm_name",
        }],
        "samples": [{
            "sample_md5hash": "test_md5_hash",
            "sample_sha1hash": "test_sha1_hash",
            "sample_sha256hash": "test_sha256_hash",
            "sample_id": 1,
            "sample_webif_url": "https://analyzer.url/",
        }],
        "submissions": [{
            "submission_sample_md5": "test_md5_hash",
            "submission_sample_sha1": "test_sha1_hash",
            "submission_sample_sha256": "test_sha256_hash",
            "submission_sample_id": 1,
            "submission_id": 4224,
            "submission_ip_ip": "127.0.0.1",
            "submission_webif_url": "https://analyzer.url/",
        }],
    }

    result = vmray_submit.vmrayProcess(json_data)

    assert {'types': 'md5', 'values': 'test_md5_hash'} in result["results"]
    assert {'types': 'sha1', 'values': 'test_sha1_hash'} in result["results"]
    assert {'types': 'sha256', 'values': 'test_sha256_hash'} in result["results"]
    assert {'tags': 'workflow:state="incomplete"', 'types': 'text', 'values': 'VMRay Sample ID: 1'} in result["results"]
    assert {'types': 'link', 'values': 'https://analyzer.url/'} in result["results"]


def test_vmrayProcess_resubmit_submission():
    json_data = {
        "errors": [{
            "error_msg": "Submission not stored because no jobs were created",
            "submission_filename": "unittest.exe"
        }],
        "jobs": [],
        "md_jobs": [],
        "reputation_jobs": [],
        "samples": [{
            "sample_md5hash": "test_md5_hash",
            "sample_sha1hash": "test_sha1_hash",
            "sample_sha256hash": "test_sha256_hash",
            "sample_id": 1,
            "sample_webif_url": "https://analyzer.url/",
        }]
    }

    result = vmray_submit.vmrayProcess(json_data)

    assert (result.get("results", False))
    assert {'types': 'md5', 'values': 'test_md5_hash'} in result["results"]
    assert {'types': 'sha1', 'values': 'test_sha1_hash'} in result["results"]
    assert {'types': 'sha256', 'values': 'test_sha256_hash'} in result["results"]
    assert {'tags': 'workflow:state="incomplete"', 'types': 'text', 'values': 'VMRay Sample ID: 1'} in result["results"]
    assert {'types': 'link', 'values': 'https://analyzer.url/'} in result["results"]


def test_handler_full_resubmit(monkeypatch, requests_mock):
    monkeypatch.setattr(vmray_submit, "vmrayProcess", mock.Mock())
    json_data = {"data": {
        "errors": [{
            "error_msg": "Submission not stored because no jobs were created",
            "submission_filename": "unittest.exe"
        }],
        "jobs": [],
        "md_jobs": [],
        "reputation_jobs": [],
        "samples": [{
            "sample_md5hash": "test_md5_hash",
            "sample_sha1hash": "test_sha1_hash",
            "sample_sha256hash": "test_sha256_hash",
            "sample_id": 1,
            "sample_webif_url": "https://analyzer.url/",
        }]
    }}
    requests_mock.post("http://localhost/rest/sample/submit", json=json_data, status_code=200)
    mock_q = {
        "attachment": "dGVzdHN0cmluZw==",
        "data": "dGVzdHN0cmluZw==",
        "config": {
            "apikey": "1234",
            "url": "http://localhost",
            "shareable": "true",
            "do_not_reanalyze": "trUe",
            "do_not_include_vmrayjobids": "False"
        }
    }

    result = vmray_submit.handler(json.dumps(mock_q))

    assert isinstance(result, mock.Mock)
