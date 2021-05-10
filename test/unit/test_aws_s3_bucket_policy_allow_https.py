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

import json
import pytest
from mock import Mock

from remediation_worker.jobs.aws_s3_bucket_policy_allow_https.aws_s3_bucket_policy_allow_https import (
    S3AllowOnlyHttpsRequest,
)


@pytest.fixture
def valid_payload():
    return """
{
    "notificationInfo": {
        "RuleId": "5c6cc5e103dcc90f363146cd",
        "Service": "S3",
        "FindingInfo": {
            "FindingId": "d0431afd-b82e-4021-8aa6-ba3cf5c60ef7",
            "ObjectId": "bucket_name",
            "ObjectChain": "{\\"cloudAccountId\\":\\"cloud_account_id\\",\\"entityId\\":\\"AWS.S3.159636093902.us-west-2.Bucket.test-remediation\\",\\"entityName\\":\\"remediation\\",\\"entityType\\":\\"AWS.S3.Bucket\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"153894897389\\",\\"provider\\":\\"AWS\\",\\"region\\":\\"us-west-2\\",\\"service\\":\\"CloudTrail\\", \\"properties\\":[{\\"name\\":\\"S3BucketName\\",\\"stringV\\":\\"remediation-cloudtrail\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestCloudtrailS3PublicAccess(object):
    def test_parse_payload(self, valid_payload):
        params = S3AllowOnlyHttpsRequest().parse(valid_payload)
        assert params["bucket_name"] == "bucket_name"
        assert params["cloud_account_id"] == "cloud_account_id"

    def test_remediate_success(self):
        client = Mock()
        action = S3AllowOnlyHttpsRequest()
        action.create_key = Mock()
        client.get_bucket_policy.return_value = {
            "ResponseMetadata": {
                "RequestId": "Z4MVPBGNWPZVDEM9",
                "HostId": "kbdViazCnratDD68N8hqAJWktBu+gTI9WKnO2eQ6CIdKAUmUyBq7A23b/T61/3mOkfY6NXk2ens=",
                "HTTPStatusCode": 200,
                "HTTPHeaders": {
                    "x-amz-id-2": "kbdViazCnratDD68N8hqAJWktBu+gTI9WKnO2eQ6CIdKAUmUyBq7A23b/T61/3mOkfY6NXk2ens=",
                    "x-amz-request-id": "Z4MVPBGNWPZVDEM9",
                    "date": "Thu, 15 Apr 2021 13:41:24 GMT",
                    "content-type": "application/json",
                    "content-length": "662",
                    "server": "AmazonS3",
                },
                "RetryAttempts": 1,
            },
            "Policy": '{"Version":"2012-10-17","Statement":[{"Sid":"AWSCloudTrailAclCheck20150319","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::mitrashtest"},{"Sid":"AWSCloudTrailWrite20150319","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::mitrashtest/AWSLogs/159636093902/*","Condition":{"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control"}}},{"Sid":"Restrict Non-https Requests","Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::mitrashtest/*"}]}',
        }

        Policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailAclCheck20150319",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": "arn:aws:s3:::mitrashtest",
                },
                {
                    "Sid": "AWSCloudTrailWrite20150319",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": "arn:aws:s3:::mitrashtest/AWSLogs/159636093902/*",
                    "Condition": {
                        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                    },
                },
                {
                    "Sid": "Restrict Non-https Requests",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::mitrashtest/*",
                },
                {
                    "Sid": "Restrict Non-https Requests",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket_name/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                },
            ],
        }

        assert action.remediate(client, "cloud_account_id", "bucket_name") == 0
        assert client.get_bucket_policy.call_count == 1
        assert client.put_bucket_policy.call_count == 1
        call_args = client.put_bucket_policy.call_args
        updated_policy = call_args[1]["Policy"]
        assert updated_policy == json.dumps(Policy)

    def test_remediate_with_exception(self):
        client = Mock()
        action = S3AllowOnlyHttpsRequest()
        with pytest.raises(Exception):
            assert action.remediate(
                client, "sg_name", "cloud_account_id", "bucket_name"
            )
