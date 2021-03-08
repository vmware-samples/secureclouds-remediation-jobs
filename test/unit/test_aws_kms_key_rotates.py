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
from mock import Mock

from remediation_worker.jobs.aws_kms_key_rotates.aws_kms_key_rotates import (
    EnableKmsKeyRotation,
)


@pytest.fixture
def valid_payload():
    return """
{
    "notificationInfo": {
        "RuleId": "5c6cc5e103dcc90f363146cd",
        "Service": "KMS",
        "FindingInfo": {
            "FindingId": "d0431afd-b82e-4021-8aa6-ba3cf5c60ef7",
            "ObjectId": "key_id",
            "ObjectChain": "{\\"cloudAccountId\\":\\"cloud_account_id\\",\\"entityId\\":\\"AWS.KMS.15960266902.us-west-2.Key.key_id\\",\\"entityName\\":\\"key_id\\",\\"entityType\\":\\"AWS.KMS.Key\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"156898827089\\",\\"provider\\":\\"AWS\\",\\"region\\":\\"us-west-2\\",\\"service\\":\\"CloudTrail\\", \\"properties\\":[{\\"name\\":\\"KeyState\\",\\"stringV\\":\\"Enabled\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestCloudtrailS3PublicAccess(object):
    def test_parse_payload(self, valid_payload):
        params = EnableKmsKeyRotation().parse(valid_payload)
        assert params["key_id"] == "key_id"
        assert params["region"] == "region"

    def test_remediate_success_with_bucket_policy_public(self):
        kms_client = Mock()
        action = EnableKmsKeyRotation()
        assert action.remediate(kms_client, "key_id", "region") == 0
        assert kms_client.enable_key_rotation.call_count == 1
        call_args = kms_client.enable_key_rotation.call_args
        key_id = call_args[1]["KeyId"]
        assert key_id == "key_id"

    def test_remediate_with_exception(self):
        kms_client = Mock()
        action = EnableKmsKeyRotation()
        with pytest.raises(Exception):
            assert action.remediate(kms_client, "key_id")
