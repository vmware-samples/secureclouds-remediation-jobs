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

import pytest
from botocore.exceptions import ClientError

from remediation_worker.jobs.s3_enable_access_logging.s3_enable_access_logging import (
    S3EnableAccessLogging,
)


@pytest.fixture
def valid_payload1():
    return """
        {
            "notificationInfo": {
                "FindingInfo": {
                    "ObjectId": "foo"
                }
            }
        }
    """


@pytest.fixture
def invalid_payload():
    return """
        {
            "notificationInfo": {
                "FindingInfo": {
                    "None": "foo"
                }
            }
        }
    """


@pytest.fixture
def full_payload():
    return "{\"cloudAccount\":{\"provider\":\"\",\"roleArn\":\"arn:aws:iam::530342348278:role/SecureStateRemediation\"},\"notificationInfo\":{\"RuleId\":\"5c6cc5cc03dcc90f3631468d\",\"RuleName\":\"\",\"RuleDisplayName\":\"\",\"Level\":\"Low\",\"Service\":\"s3\",\"FindingInfo\":{\"FindingId\":\"05eedc79-65b5-4774-8a6a-cfffb17a3a99\",\"ObjectId\":\"rule-executor-s3-test-892fbb42-45ee-489b-bcc9-e9a4dc285ea0\",\"ObjectChain\":\"{\\\"cloudAccountId\\\":\\\"530342348278\\\",\\\"creationTime\\\":\\\"2020-06-23T21:40:33.000Z\\\",\\\"depthCount\\\":{\\\"depth_0\\\":1,\\\"depth_1\\\":1},\\\"entityId\\\":\\\"AWS.S3.530342348278.us-east-1.Bucket.rule-executor-s3-test-892fbb42-45ee-489b-bcc9-e9a4dc285ea0\\\",\\\"entityName\\\":\\\"rule-executor-s3-test-892fbb42-45ee-489b-bcc9-e9a4dc285ea0\\\",\\\"entityType\\\":\\\"AWS.S3.Bucket\\\",\\\"lastUpdateTime\\\":\\\"2020-06-23T21:40:33.000Z\\\",\\\"partitionKey\\\":\\\"530342348278\\\",\\\"properties\\\":[{\\\"name\\\":\\\"BucketName\\\",\\\"stringV\\\":\\\"rule-executor-s3-test-892fbb42-45ee-489b-bcc9-e9a4dc285ea0\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"VersioningStatus\\\",\\\"stringV\\\":\\\"Enabled\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"CreationDate\\\",\\\"stringV\\\":\\\"2020-06-22T20:48:49.000Z\\\",\\\"type\\\":\\\"datetime\\\"},{\\\"boolV\\\":false,\\\"name\\\":\\\"ReplicationEnabled\\\",\\\"type\\\":\\\"bool\\\"},{\\\"name\\\":\\\"VersioningMFADelete\\\",\\\"stringV\\\":\\\"Disabled\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"Location\\\",\\\"stringV\\\":\\\"us-east-1\\\",\\\"type\\\":\\\"string\\\"},{\\\"boolV\\\":false,\\\"name\\\":\\\"LoggingEnabled\\\",\\\"type\\\":\\\"bool\\\"}],\\\"provider\\\":\\\"AWS\\\",\\\"region\\\":\\\"us-east-1\\\",\\\"service\\\":\\\"S3\\\"}\",\"CloudTags\":null,\"RiskScore\":10,\"Region\":\"us-east-1\",\"Service\":\"s3\"}},\"autoRemediate\":false}"

class TestS3EnableAccessLogging(object):
    def test_parse_payload_success(self, full_payload):
        obj = S3EnableAccessLogging()
        result = obj.parse(full_payload)
        assert "source_bucket" in result

    def test_parse_payload_with_missing_param(self, invalid_payload):
        obj = S3EnableAccessLogging()
        with pytest.raises(Exception):
            assert obj.parse(invalid_payload)

    def test_remediate_success(self):
        class TestClient(object):
            def put_bucket_logging(self, **kwargs):
                return None

            def put_bucket_acl(self, **kwargs):
                return None

            def get_bucket_acl(self, **kwargs):
                return {'ResponseMetadata': None, 'Grants': [{'hi': 'bye'}]}

            def create_bucket(self, **kwargs):
                return None

        client = TestClient()
        action = S3EnableAccessLogging()
        assert (
                action.remediate("region", client, "source_bucket", "target_bucket", "target_prefix")
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
        action = S3EnableAccessLogging()
        with pytest.raises(Exception):
            assert action.remediate(
                "region", client, "source_bucket", "target_bucket", "target_prefix"
            )
