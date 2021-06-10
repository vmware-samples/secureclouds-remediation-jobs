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
