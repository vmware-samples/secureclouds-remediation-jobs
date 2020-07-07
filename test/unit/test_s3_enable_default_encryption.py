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
from remediation_worker.jobs.s3_enable_default_encryption.s3_enable_default_encryption import (
    S3EnableDefaultEncryption,
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


class TestS3EnableDefaultEncryption(object):
    def test_parse_payload_success(self, valid_payload1):
        obj = S3EnableDefaultEncryption()
        result = obj.parse(valid_payload1)
        assert "bucket_name" in result

    def test_parse_payload_with_missing_param(self, invalid_payload):
        obj = S3EnableDefaultEncryption()
        with pytest.raises(Exception):
            assert obj.parse(invalid_payload)

    def test_remediate_success(self):
        class TestClient(object):
            def put_bucket_encryption(self, **kwargs):
                return None

        client = TestClient()
        action = S3EnableDefaultEncryption()
        assert action.remediate(client, "bucket_name") == 0

    def test_remediate_with_exception(self):
        class TestClient(object):
            def put_bucket_encryption(self, **kwargs):
                raise ClientError(
                    {
                        "Error": {
                            "Code": "NotFound",
                            "Message": "InvalidPermission.NotFound",
                        }
                    },
                    "TestS3EnableDefaultEncryption",
                )

        client = TestClient()
        action = S3EnableDefaultEncryption()
        with pytest.raises(Exception):
            assert action.remediate(client, "bucket_name")
