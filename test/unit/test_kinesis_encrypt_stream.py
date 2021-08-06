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

from remediation_worker.jobs.kinesis_encrypt_stream.kinesis_encrypt_stream import KinesisEncryptStream 

@pytest.fixture
def valid_payload():
    return """ {
    "notificationInfo": {
        "FindingInfo": {
            "ObjectId": "kinesis-stream",
            "Region": "us-east-1"
        }
    }
  }
"""


class TestKinesisEncryptStream:
    def test_parse_payload(self, valid_payload):
        obj = KinesisEncryptStream()
        param = obj.parse(valid_payload)
        assert "stream_name" in param
        assert param["stream_name"] == "kinesis-stream"
        assert "region" in param
        assert param["region"] == "us-east-1"

    def test_remediate_success(self):
        class TestClient(object):
            def start_stream_encryption(self, **kwargs):
                return 0

            def describe_stream(self, **kwargs):
                stream = {'StreamDescription': {'EncryptionType':"NONE"}}
                return stream

        client = TestClient()
        obj = KinesisEncryptStream()
        assert obj.remediate("stream_name", client, "us-west1") == 0

    def test_remediate_not_success_resource_not_found(self):
        class TestClient(object):
            def start_stream_encryption(self, **kwargs):
                return 0

            def describe_stream(self, **kwargs):
                raise ClientError(
                    {
                        "Error": {
                            "Code": "ResourceNotFoundException",
                            "Message": "ResourceNotFoundException for reason",
                        }
                    },
                    "KinesisEncryptStream",
                )

        client = TestClient()
        obj = KinesisEncryptStream()
        assert obj.remediate("stream_name", client, "us-west1") == 1

    def test_remediate_not_success_limit_exceed(self):
        class TestClient(object):
            def start_stream_encryption(self, **kwargs):
                return 0

            def describe_stream(self, **kwargs):
                raise ClientError(
                    {
                        "Error": {
                            "Code": "LimitExceededException",
                            "Message": "LimitExceededException for reason",
                        }
                    },
                    "KinesisEncryptStream",
                )

        client = TestClient()
        obj = KinesisEncryptStream()
        assert obj.remediate("stream_name", client, "us-west1") == 1

    def test_remediate_not_success_resource_in_use(self):
        class TestClient(object):
            def describe_stream(self, **kwargs):
                stream = {'StreamDescription': {'EncryptionType':"NONE"}}
                return stream

            def start_stream_encryption(self, **kwargs):
                raise ClientError(
                    {
                        "Error": {
                            "Code": "ResourceInUseException",
                            "Message": "ResourceInUseException for reason",
                        }
                    },
                    "KinesisEncryptStream",
                )

        client = TestClient()
        obj = KinesisEncryptStream()
        assert obj.remediate("stream_name", client, "us-west1") == 1

    def test_remediate_not_success_other_aws_exceptions(self):
        class TestClient(object):
            def describe_stream(self, **kwargs):
                stream = {'StreamDescription': {'EncryptionType':"NONE"}}
                return stream

            def start_stream_encryption(self, **kwargs):
                raise ClientError(
                    {
                        "Error": {
                            "Code": "InvalidArgumentException",
                            "Message": "InvalidArgumentException for reason",
                        }
                    },
                    "KinesisEncryptStream",
                )

        client = TestClient()
        obj = KinesisEncryptStream()
        assert obj.remediate("stream_name", client, "us-west1") == 1

    def test_remediate_not_success_other_exceptions(self):
        class TestClient(object):
            def describe_stream(self, **kwargs):
                stream = {'StreamDescription': {'EncryptionType':"NONE"}}
                return stream

            def start_stream_encryption(self, **kwargs):
                raise Exception('This is the exception you expect to handle')

        client = TestClient()
        obj = KinesisEncryptStream()
        assert obj.remediate("stream_name", client, "us-west1") == 1

