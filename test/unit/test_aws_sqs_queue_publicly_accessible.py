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

from remediation_worker.jobs.aws_sqs_queue_publicly_accessible.aws_sqs_queue_publicly_accessible import (
    SqsQueuePubliclyAccessible,
)


@pytest.fixture
def valid_payload():
    return """
{
    "notificationInfo": {
        "RuleId": "5c6cc5e103dcc90f363146cd",
        "Service": "SQS",
        "FindingInfo": {
            "FindingId": "d0431afd-b82e-4021-8aa6-ba3cf5c60ef7",
            "ObjectId": "queue_name",
            "ObjectChain": "{\\"cloudAccountId\\":\\"cloud_account_id\\",\\"entityId\\":\\"AWS.SQS.159636093902.us-west-2.Queue.test-remediation\\",\\"entityName\\":\\"test-remediation\\",\\"entityType\\":\\"AWS.SQS.Queue\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"153894897389\\",\\"provider\\":\\"AWS\\",\\"region\\":\\"us-west-2\\",\\"service\\":\\"CloudTrail\\", \\"properties\\":[{\\"name\\":\\"S3BucketName\\",\\"stringV\\":\\"remediation-cloudtrail\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestSqsPublicAccess(object):
    def test_parse_payload(self, valid_payload):
        params = SqsQueuePubliclyAccessible().parse(valid_payload)
        assert params["queue_name"] == "queue_name"
        assert params["cloud_account_id"] == "cloud_account_id"
        assert params["region"] == "region"

    def test_remediate_success(self):
        client = Mock()
        action = SqsQueuePubliclyAccessible()
        client.get_queue_url.return_value = {
            "QueueUrl": "https://us-east-2.queue.amazonaws.com/27893578330/remediation-test-queue"
        }
        client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": '{"Version":"2008-10-17","Id":"__default_policy_ID","Statement":[{"Sid":"__owner_statement","Effect":"Allow","Principal":{"AWS":"*"},"Action":"SQS:*","Resource":"arn:aws:sqs:us-east-2:27893578330:remediation-test-queue"},{"Sid":"__owner_statement2","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::27893578330:root"},"Action":"SQS:*","Resource":"arn:aws:sqs:us-east-2:27893578330:remediation-test-queue"}]}'
            },
            "ResponseMetadata": {
                "RequestId": "c6239f68-64ea-541d-93bd-c79018befd86",
                "HTTPStatusCode": 200,
                "HTTPHeaders": {
                    "x-amzn-requestid": "c6239f7898-64aa-571d-93bd-c79818befd86",
                    "date": "Tue, 20 Apr 2021 06:52:04 GMT",
                    "content-type": "text/xml",
                    "content-length": "1264",
                },
                "RetryAttempts": 0,
            },
        }

        assert action.remediate(client, "region", "cloud_account_id", "queue_name") == 0
        assert client.remove_permission.call_count == 1

    def test_remediate_with_exception(self):
        client = Mock()
        action = SqsQueuePubliclyAccessible()
        with pytest.raises(Exception):
            assert action.remediate(client, "cloud_account_id")
