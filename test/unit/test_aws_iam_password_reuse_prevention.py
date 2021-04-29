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

from remediation_worker.jobs.aws_iam_password_policy_min_length.aws_iam_password_policy_min_length import (
    SetPasswordMinimumLength,
)


@pytest.fixture
def valid_payload():
    return """
{
    "notificationInfo": {
        "RuleId": "5c6cc5e103dcc90f363146cd",
        "Service": "IAM",
        "FindingInfo": {
            "FindingId": "d0431afd-b82e-4021-8aa6-ba3cf5c60ef7",
            "ObjectId": "account_id",
            "ObjectChain": "{\\"cloudAccountId\\":\\"cloud_account_id\\",\\"entityId\\":\\"AWS.IAM.159026902.us-west-2.Key.key_id\\",\\"entityName\\":\\"key_id\\",\\"entityType\\":\\"AWS.IAM.AccountPasswordPolicy\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"156898827089\\",\\"provider\\":\\"AWS\\",\\"region\\":\\"us-west-2\\",\\"service\\":\\"CloudTrail\\", \\"properties\\":[{\\"name\\":\\"KeyState\\",\\"stringV\\":\\"Enabled\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestSetPasswordMinLength(object):
    def test_parse_payload(self, valid_payload):
        params = SetPasswordMinimumLength().parse(valid_payload)
        assert params["account_id"] == "account_id"

    def test_remediate_success(self):
        client = Mock()
        action = SetPasswordMinimumLength()
        assert action.remediate(client, "account_id") == 0
        assert client.update_account_password_policy.call_count == 1
        call_args = client.update_account_password_policy.call_args
        password_reuse_policy = call_args[1]["MinimumPasswordLength"]
        assert password_reuse_policy == 14

    def test_remediate_with_exception(self):
        client = Mock()
        action = SetPasswordMinimumLength()
        with pytest.raises(Exception):
            assert action.remediate(client, "account_id")
