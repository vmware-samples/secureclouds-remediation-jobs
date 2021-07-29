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

from remediation_worker.jobs.aws_ec2_default_security_group_traffic.aws_ec2_default_security_group_traffic import (
    DefaultSecurityGroupRemoveRules,
)


@pytest.fixture
def valid_payload():
    return """
{
    "notificationInfo": {
        "RuleId": "5c6cc5e103dcc90f363146cd",
        "Service": "EC2",
        "FindingInfo": {
            "FindingId": "d0431afd-b82e-4021-8aa6-ba3cf5c60ef7",
            "ObjectId": "security_group_id",
            "ObjectChain": "{\\"cloudAccountId\\":\\"cloud_account_id\\",\\"entityId\\":\\"AWS.EC2.159636093902.us-west-2.Trail.test-remediation\\",\\"entityName\\":\\"remediation-cloudtrail\\",\\"entityType\\":\\"AWS.CloudTrail.Trail\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"153894897389\\",\\"provider\\":\\"AWS\\",\\"region\\":\\"us-west-2\\",\\"service\\":\\"EC2\\", \\"properties\\":[{\\"name\\":\\"S3BucketName\\",\\"stringV\\":\\"remediation-cloudtrail\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestCloudtrailS3PublicAccess(object):
    def test_parse_payload(self, valid_payload):
        params = DefaultSecurityGroupRemoveRules().parse(valid_payload)
        assert params["security_group_id"] == "security_group_id"
        assert params["cloud_account_id"] == "cloud_account_id"
        assert params["region"] == "region"

    def test_remediate_success(self):
        client = Mock()
        action = DefaultSecurityGroupRemoveRules()

        assert (
            action.remediate(client, "security_group_id", "region", "cloud_account_id")
            == 0
        )
        assert client.describe_security_groups.call_count == 1

    def test_remediate_with_exception(self):
        client = Mock()
        action = DefaultSecurityGroupRemoveRules()
        with pytest.raises(Exception):
            assert action.remediate(client, "cloud_account_id")