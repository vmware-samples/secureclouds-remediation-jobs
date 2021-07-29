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

from remediation_worker.jobs.aws_iam_server_certificate_expired.aws_iam_server_certificate_expired import (
    DeleteExpiredServerCertificate,
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
            "ObjectId": "certificate_name",
            "ObjectChain": "{\\"cloudAccountId\\":\\"cloud_account_id\\",\\"entityId\\":\\"AWS.IAM.159026902.us-west-2.Key.key_id\\",\\"entityName\\":\\"key_id\\",\\"entityType\\":\\"AWS.IAM.AccountPasswordPolicy\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"156898827089\\",\\"provider\\":\\"AWS\\",\\"region\\":\\"us-west-2\\",\\"service\\":\\"CloudTrail\\", \\"properties\\":[{\\"name\\":\\"KeyState\\",\\"stringV\\":\\"Enabled\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestDeleteExpiredServerCertificate(object):
    def test_parse_payload(self, valid_payload):
        params = DeleteExpiredServerCertificate().parse(valid_payload)
        assert params["certificate_name"] == "certificate_name"

    def test_remediate_success(self):
        client = Mock()
        action = DeleteExpiredServerCertificate()
        assert action.remediate(client, "certificate_name") == 0

    def test_remediate_with_exception(self):
        client = Mock()
        action = DeleteExpiredServerCertificate()
        with pytest.raises(Exception):
            assert action.remediate(client, "certificate_name")
