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

from remediation_worker.jobs.aws_cloudtrail_logs_encrypted.aws_cloudtrail_logs_encrypted import (
    CloudtrailEncryptLogs,
)


@pytest.fixture
def valid_payload():
    return """
{
    "notificationInfo": {
        "RuleId": "5c6cc5e103dcc90f363146cd",
        "Service": "CloudTrail",
        "FindingInfo": {
            "FindingId": "d0431afd-b82e-4021-8aa6-ba3cf5c60ef7",
            "ObjectId": "cloudtrail_name",
            "ObjectChain": "{\\"cloudAccountId\\":\\"cloud_account_id\\",\\"entityId\\":\\"AWS.CloudTrail.159636093902.us-west-2.Trail.test-remediation\\",\\"entityName\\":\\"remediation-cloudtrail\\",\\"entityType\\":\\"AWS.CloudTrail.Trail\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"153894897389\\",\\"provider\\":\\"AWS\\",\\"region\\":\\"us-west-2\\",\\"service\\":\\"CloudTrail\\", \\"properties\\":[{\\"name\\":\\"S3BucketName\\",\\"stringV\\":\\"remediation-cloudtrail\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestCloudtrailS3PublicAccess(object):
    def test_parse_payload(self, valid_payload):
        params = CloudtrailEncryptLogs().parse(valid_payload)
        assert params["cloudtrail_name"] == "cloudtrail_name"
        assert params["cloud_account_id"] == "cloud_account_id"
        assert params["region"] == "region"

    def test_remediate_success_with_bucket_policy_public(self):
        s3_client = Mock()
        cloudtrail_client = Mock()
        action = CloudtrailEncryptLogs()
        action.create_key = Mock()
        cloudtrail_client.get_trail.return_value = {
            "Trail": {
                "Name": "cloudtrail_name",
                "S3BucketName": "remediation-cloudtrail",
            }
        }
        s3_client.get_bucket_location.return_value = {"LocationConstraint": "us-west-2"}
        action.create_key.return_value = "arn:aws:kms:us-west-2:cloud_account_id:key/8f5234f8-b223-4a20-8355-c7a242eac048"

        assert (
            action.remediate(
                "region",
                s3_client,
                cloudtrail_client,
                "cloudtrail_name",
                "cloud_account_id",
            )
            == 0
        )
        assert cloudtrail_client.update_trail.call_count == 1
        call_args = cloudtrail_client.update_trail.call_args
        updated_trail = call_args[1]["KmsKeyId"]
        assert updated_trail == action.create_key.return_value

    def test_remediate_with_exception(self):
        s3_client = Mock()
        cloudtrail_client = Mock()
        action = CloudtrailEncryptLogs()
        with pytest.raises(Exception):
            assert action.remediate(s3_client, cloudtrail_client, "cloud_account_id")
