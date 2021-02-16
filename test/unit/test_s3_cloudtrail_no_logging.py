# Copyright (c) 2020 VMware Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json

import pytest
from mock import Mock
from botocore.exceptions import ClientError

from remediation_worker.jobs.s3_cloudtrail_no_logging.s3_cloudtrail_no_logging import (
    CloudtrailS3EnableAccessLogging,
    SelfRemediationError,
)


@pytest.fixture
def valid_payload():
    return json.dumps({"notificationInfo": {"FindingInfo": {"ObjectId": "foo"}}})


@pytest.fixture
def invalid_payload():
    return json.dumps({"notificationInfo": {"FindingInfo": {"None": "foo"}}})


@pytest.fixture
def full_payload():
    return json.dumps(
        {
            "notificationInfo": {
                "RuleId": "5c6cc5cc03dcc90f3631468d",
                "RuleName": "",
                "RuleDisplayName": "",
                "Level": "Low",
                "Service": "s3",
                "FindingInfo": {
                    "FindingId": "05eedc79-65b5-4774-8a6a-cfffb17a3a99",
                    "ObjectId": "rule-executor-s3-test-892fbb42-45ee-489b-bcc9-e9a4dc285ea0",
                    "ObjectChain": json.dumps(
                        {
                            "cloudAccountId": "530342348278",
                            "creationTime": "2020-06-23T21:40:33.000Z",
                            "depthCount": {"depth_0": 1, "depth_1": 1},
                            "entityId": "AWS.S3.530342348278.us-east-1.Bucket.rule-executor-s3-test-892fbb42-45ee-489b-bcc9-e9a4dc285ea0",  # noqa: E501
                            "entityName": "rule-executor-s3-test-892fbb42-45ee-489b-bcc9-e9a4dc285ea0",
                            "entityType": "AWS.S3.Bucket",
                            "lastUpdateTime": "2020-06-23T21:40:33.000Z",
                            "partitionKey": "530342348278",
                            "properties": [
                                {
                                    "name": "BucketName",
                                    "stringV": "rule-executor-s3-test-892fbb42-45ee-489b-bcc9-e9a4dc285ea0",
                                    "type": "string",
                                },
                                {
                                    "name": "VersioningStatus",
                                    "stringV": "Enabled",
                                    "type": "string",
                                },
                                {
                                    "name": "CreationDate",
                                    "stringV": "2020-06-22T20:48:49.000Z",
                                    "type": "datetime",
                                },
                                {
                                    "boolV": False,
                                    "name": "ReplicationEnabled",
                                    "type": "bool",
                                },
                                {
                                    "name": "VersioningMFADelete",
                                    "stringV": "Disabled",
                                    "type": "string",
                                },
                                {
                                    "name": "Location",
                                    "stringV": "us-east-1",
                                    "type": "string",
                                },
                                {
                                    "boolV": False,
                                    "name": "LoggingEnabled",
                                    "type": "bool",
                                },
                            ],
                            "provider": "AWS",
                            "region": "us-east-1",
                            "service": "S3",
                        }
                    ),
                    "CloudTags": None,
                    "RiskScore": 10,
                    "Region": "us-east-1",
                    "Service": "s3",
                },
            },
            "autoRemediate": False,
        }
    )


@pytest.fixture
def self_payload():
    return json.dumps(
        {
            "notificationInfo": {
                "RuleId": "5c6cc5cc03dcc90f3631468d",
                "RuleName": "",
                "RuleDisplayName": "",
                "Level": "Low",
                "Service": "s3",
                "FindingInfo": {
                    "FindingId": "05eedc79-65b5-4774-8a6a-cfffb17a3a99",
                    "ObjectId": "vss-logging-target-530342348278-us-east-1",
                    "ObjectChain": "{"
                    '    "cloudAccountId": "530342348278",'
                    '    "creationTime": "2020-06-23T21:40:33.000Z",'
                    '    "depthCount": {'
                    '        "depth_0": 1,'
                    '        "depth_1": 1'
                    "    },"
                    '    "entityId": "AWS.S3.530342348278.us-east-1.Bucket.rule-executor-s3-test-892fbb42-45ee-489b-bcc9-e9a4dc285ea0",'  # noqa: E501
                    '    "entityName": "rule-executor-s3-test-892fbb42-45ee-489b-bcc9-e9a4dc285ea0",'
                    '    "entityType": "AWS.S3.Bucket",'
                    '    "lastUpdateTime": "2020-06-23T21:40:33.000Z",'
                    '    "partitionKey": "530342348278",'
                    '    "properties": [{'
                    '        "name": "BucketName",'
                    '        "stringV": "rule-executor-s3-test-892fbb42-45ee-489b-bcc9-e9a4dc285ea0",'
                    '        "type": "string"'
                    "    }, {"
                    '        "name": "VersioningStatus",'
                    '        "stringV": "Enabled",'
                    '        "type": "string"'
                    "    }, {"
                    '        "name": "CreationDate",'
                    '        "stringV": "2020-06-22T20:48:49.000Z",'
                    '        "type": "datetime"'
                    "    }, {"
                    '        "boolV": false,'
                    '        "name": "ReplicationEnabled",'
                    '        "type": "bool"'
                    "    }, {"
                    '        "name": "VersioningMFADelete",'
                    '        "stringV": "Disabled",'
                    '        "type": "string"'
                    "    }, {"
                    '        "name": "Location",'
                    '        "stringV": "us-east-1",'
                    '        "type": "string"'
                    "    }, {"
                    '        "boolV": false,'
                    '        "name": "LoggingEnabled",'
                    '        "type": "bool"'
                    "    }],"
                    '    "provider": "AWS",'
                    '    "region": "us-east-1",'
                    '    "service": "S3"'
                    "}",
                    "CloudTags": None,
                    "RiskScore": 10,
                    "Region": "us-east-1",
                    "Service": "s3",
                },
            },
            "autoRemediate": False,
        }
    )


class TestS3EnableAccessLogging(object):
    def test_parse_payload_success(self, full_payload):
        obj = CloudtrailS3EnableAccessLogging()
        result = obj.parse(full_payload)
        assert "source_bucket" in result

    def test_parse_payload_with_missing_param(self, invalid_payload):
        obj = CloudtrailS3EnableAccessLogging()
        with pytest.raises(Exception):
            assert obj.parse(invalid_payload)

    def test_remediate_success(self):
        class TestClient(object):
            def put_bucket_logging(self, **kwargs):
                return None

            def put_bucket_acl(self, **kwargs):
                return None

            def get_bucket_acl(self, **kwargs):
                return {"ResponseMetadata": None, "Grants": [{"hi": "bye"}]}

            def create_bucket(self, **kwargs):
                return None

            def head_bucket(self, **kwargs):
                return {"ResponseMetadata": None}

        client = TestClient()
        action = CloudtrailS3EnableAccessLogging()
        assert (
            action.remediate(
                client=client,
                region="region",
                source_bucket="source_bucket",
                target_bucket="target_bucket",
                target_prefix="target_prefix",
            )
            == 0
        )

    def test_remediate_with_exception(self):
        class TestClient(object):
            def put_bucket_logging(self, **kwargs):
                raise ClientError(
                    {
                        "Error": {
                            "Code": "NotFound",
                            "Message": "InvalidPermission.NotFound",
                        }
                    },
                    "TestS3EnableAccessLogging",
                )

        client = TestClient()
        action = CloudtrailS3EnableAccessLogging()
        with pytest.raises(Exception):
            assert action.remediate(
                "region", client, "source_bucket", "target_bucket", "target_prefix"
            )

    def test_dont_log_to_self(self, self_payload):
        with pytest.raises(SelfRemediationError):
            assert CloudtrailS3EnableAccessLogging().run([None, self_payload])

    def test_check_log_delivery(self):
        acl = {
            "Grants": [
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                    },
                    "Permission": "WRITE",
                }
            ]
        }

        action = CloudtrailS3EnableAccessLogging()
        write_enabled, read_acp_enabled = action.check_log_delivery_permissions(acl)
        assert write_enabled
        assert not read_acp_enabled

    def test_grant_log_delivery_permissions(self):
        client = Mock()
        client.get_bucket_acl.return_value = {
            "ResponseMetadata": {
                "RequestId": "6B0F579EDDCCAB3C",
                "HostId": "9Csk0PXuRLyPhcKimBPbhfEmwQywAXPiWVWdpZPV+rjwVZO1DJMEKD/M65RJL+GguB3UMhOmpAQ=",
                "HTTPStatusCode": 200,
                "HTTPHeaders": {
                    "x-amz-id-2": "9Csk0PXuRLyPhcKimBPbhfEmwQywAXPiWVWdpZPV+rjwVZO1DJMEKD/M65RJL+GguB3UMhOmpAQ=",
                    "x-amz-request-id": "6B0F579EDDCCAB3C",
                    "date": "Wed, 16 Sep 2020 16:57:36 GMT",
                },
                "RetryAttempts": 0,
            },
            "Owner": {
                "DisplayName": "awsmasteremail",
                "ID": "b101f924005dbb04273644ca983ef2ea93d43ad46757f21f65c40d48d75368c3",
            },
            "Grants": [
                {
                    "Grantee": {
                        "DisplayName": "awsmasteremail",
                        "ID": "b101f924005dbb04273644ca983ef2ea93d43ad46757f21f65c40d48d75368c3",
                        "Type": "CanonicalUser",
                    },
                    "Permission": "FULL_CONTROL",
                },
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                    },
                    "Permission": "READ_ACP",
                },
            ],
        }

        bucket_name = "my_bucket"
        action = CloudtrailS3EnableAccessLogging()
        action.grant_log_delivery_permissions(client, bucket_name)
        assert client.put_bucket_acl.call_count == 1
        call_args = client.put_bucket_acl.call_args.kwargs

        assert len(call_args) == 2
        assert call_args.get("Bucket") == bucket_name

        acp = call_args.get("AccessControlPolicy")
        assert acp is not None
        assert len(acp["Grants"]) >= 2
        write_granted, read_granted = action.check_log_delivery_permissions(acp)
        assert write_granted
        assert read_granted
