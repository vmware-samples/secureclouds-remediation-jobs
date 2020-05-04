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
from remediation_worker.jobs.s3_list_buckets.s3_list_buckets import S3ListBuckets


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


class TestS3ListBuckets(object):
    def test_parse_payload_success(self, valid_payload1):
        obj = S3ListBuckets()
        obj.parse(valid_payload1)

    def test_remediate_success(self):
        class TestClient(object):
            def list_buckets(self, **kwargs):
                return {"Buckets": [{"Name": "Bucket"}]}

        client = TestClient()
        action = S3ListBuckets()
        assert action.remediate(client) == 0

    def test_remediate_with_exception(self):
        class TestClient(object):
            def list_buckets(self, **kwargs):
                raise ClientError(
                    {
                        "Error": {
                            "Code": "NotFound",
                            "Message": "InvalidPermission.NotFound",
                        }
                    },
                    "S3ListBuckets",
                )

        client = TestClient()
        action = S3ListBuckets()
        with pytest.raises(Exception):
            assert action.remediate(client)
