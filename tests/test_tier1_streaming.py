import asyncio
import json

from app.parsers.factory import ParserFactory
from app.schemas.log_event import LogEvent
from app.services.queue_service import StreamingQueueService
from app.services.syslog_service import SyslogService, parse_syslog_framing


def test_rfc5424_and_rfc3164_syslog_framing():
    # RFC 5424 test
    rfc5424_raw = '<165>1 2026-11-21T04:00:00Z webserver01 nginx 1234 ID47 - 192.168.1.50 - - "GET /login HTTP/1.1" 200 450'
    res_5424 = parse_syslog_framing(rfc5424_raw)
    assert res_5424["format"] == "RFC5424"
    assert res_5424["pri"] == 165
    assert res_5424["facility"] == 20
    assert res_5424["severity"] == 5
    assert res_5424["hostname"] == "webserver01"
    assert res_5424["app_name"] == "nginx"
    assert "192.168.1.50" in res_5424["msg"]

    # RFC 3164 test
    rfc3164_raw = "<34>Oct 11 22:14:15 firebox sshd[4092]: Failed password for root from 203.0.113.5 port 22"
    res_3164 = parse_syslog_framing(rfc3164_raw)
    assert res_3164["format"] == "RFC3164"
    assert res_3164["pri"] == 34
    assert res_3164["hostname"] == "firebox"
    assert res_3164["app_name"] == "sshd"
    assert "Failed password" in res_3164["msg"]


def test_linux_auth_parser():
    parser = ParserFactory.get_parser("linux_auth")

    # 1. SSH Failed login
    failed_line = "Nov 21 04:15:32 server sshd[1204]: Failed password for invalid user admin from 198.51.100.22 port 52341 ssh2"
    assert parser.validate(failed_line) is True
    event = parser.parse_line(failed_line)
    assert event is not None
    assert event.source_ip == "198.51.100.22"
    assert event.user == "admin"
    assert event.action == "SSH_FAILED_LOGIN"
    assert event.status_code == 401

    # 2. SSH Accepted login
    accepted_line = "Nov 21 04:16:01 server sshd[1205]: Accepted publickey for ubuntu from 192.168.1.10 port 49123 ssh2"
    event_acc = parser.parse_line(accepted_line)
    assert event_acc is not None
    assert event_acc.source_ip == "192.168.1.10"
    assert event_acc.user == "ubuntu"
    assert event_acc.action == "SSH_ACCEPTED_LOGIN"
    assert event_acc.status_code == 200

    # 3. Sudo execution
    sudo_line = "Nov 21 04:17:10 server sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    event_sudo = parser.parse_line(sudo_line)
    assert event_sudo is not None
    assert event_sudo.user == "analyst"
    assert event_sudo.action == "SUDO_EXEC"
    assert event_sudo.command_line == "/bin/cat /etc/shadow"


def test_windows_event_parser():
    parser = ParserFactory.get_parser("windows_event")

    # Event 4625 Failed Logon JSON
    failed_logon_json = json.dumps(
        {
            "EventID": 4625,
            "Computer": "DC01.corp.local",
            "EventData": {
                "TargetUserName": "Administrator",
                "IpAddress": "10.0.0.99",
                "Status": "0xC000006D",
            },
        }
    )
    assert parser.validate(failed_logon_json) is True
    event = parser.parse_line(failed_logon_json)
    assert event is not None
    assert event.event_id == "4625"
    assert event.source_ip == "10.0.0.99"
    assert event.user == "Administrator"
    assert event.action == "LOGON_FAILURE"
    assert event.status_code == 401

    # Event 4688 Process Creation JSON
    proc_create_json = json.dumps(
        {
            "EventID": 4688,
            "Computer": "WORKSTATION-42",
            "EventData": {
                "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c whoami",
                "SubjectUserName": "jsmith",
            },
        }
    )
    event_proc = parser.parse_line(proc_create_json)
    assert event_proc is not None
    assert event_proc.event_id == "4688"
    assert event_proc.command_line == "cmd.exe /c whoami"
    assert event_proc.action == "PROCESS_CREATION"


def test_cloudtrail_parser():
    parser = ParserFactory.get_parser("cloudtrail")
    ct_log = json.dumps(
        {
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateAccessKey",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "198.51.100.77",
            "userIdentity": {"userName": "compromised-dev"},
            "errorCode": "AccessDenied",
        }
    )
    assert parser.validate(ct_log) is True
    event = parser.parse_line(ct_log)
    assert event is not None
    assert event.action == "AWS_CREATEACCESSKEY"
    assert event.source_ip == "198.51.100.77"
    assert event.user == "compromised-dev"
    assert event.status_code == 403


def test_streaming_queue_service():
    queue = StreamingQueueService(maxsize=10, batch_size=2)
    ev1 = LogEvent(raw_log="test1", parser_name="test")
    ev2 = LogEvent(raw_log="test2", parser_name="test")

    assert queue.enqueue(ev1) is True
    assert queue.enqueue(ev2) is True
    metrics = queue.get_metrics()
    assert metrics["current_queue_depth"] == 2
    assert metrics["total_enqueued"] == 2
    assert metrics["total_dropped"] == 0
