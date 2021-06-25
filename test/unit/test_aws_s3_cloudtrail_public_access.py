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
from botocore.exceptions import ClientError

from remediation_worker.jobs.aws_s3_cloudtrail_public_access.aws_s3_cloudtrail_public_access import (
    CloudtrailS3RemovePublicAccess,
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
            "ObjectId": "CloudTrail_name",
            "ObjectChain": "{\\"cloudAccountId\\":\\"cloud_account_id\\",\\"entityId\\":\\"AWS.CloudTrail.159636093902.us-west-2.Trail.test-remediation\\",\\"entityName\\":\\"remediation-cloudtrail\\",\\"entityType\\":\\"AWS.CloudTrail.Trail\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"153894897389\\",\\"provider\\":\\"AWS\\",\\"region\\":\\"us-west-2\\",\\"service\\":\\"CloudTrail\\", \\"properties\\":[{\\"name\\":\\"S3BucketName\\",\\"stringV\\":\\"remediation-cloudtrail\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestCloudtrailS3PublicAccess(object):
    def test_parse_payload(self, valid_payload):
        params = CloudtrailS3RemovePublicAccess().parse(valid_payload)
        assert params["region"] == "region"
        assert params["cloudtrail_name"] == "CloudTrail_name"
        assert params["cloud_account_id"] == "cloud_account_id"

    def test_remediate_success_with_bucket_policy_public(self):
        client = Mock()
        cloudtrail_client = Mock()
        action = CloudtrailS3RemovePublicAccess()
        trail = {
            "Trail": {
                "Name": "CloudTrail_name",
                "S3BucketName": "remediation-cloudtrail",
            }
        }
        cloudtrail_client.get_trail.return_value = trail
        bucket_status = {
            "ResponseMetadata": {
                "RequestId": "9B28R8BGSR67A459",
                "HostId": "aS/3JTmp+hjghfjxfhc4VznkMTTkjhbjkKMCs93cfTCcC6R2rE3SIVziHRDFg=",
                "HTTPStatusCode": 200,
                "HTTPHeaders": {
                    "x-amz-id-2": "aS/3JTmp+hjghfjxfhc4VznkMTTkjhbjkKMCs93cfTCcC6R2rE3SIVziHRDFg=",
                    "x-amz-request-id": "9B28R8BGSR67A459",
                    "date": "Wed, 27 Jan 2021 14:51:32 GMT",
                    "transfer-encoding": "chunked",
                    "server": "AmazonS3",
                },
                "RetryAttempts": 0,
            },
            "PolicyStatus": {"IsPublic": True},
        }
        client.get_bucket_policy_status.return_value = bucket_status
        client.get_bucket_policy.return_value = {
            "ResponseMetadata": {
                "RequestId": "EPFRBXATAM2JCGDP",
                "HostId": "M4bxrGZTQykEqOjq0WZ9cQKDhdatiPqCHV8GsZCdRSFn8bOXF4441q9vPzR/33ca9xePha+zhCw=",
                "HTTPStatusCode": 200,
                "HTTPHeaders": {
                    "x-amz-id-2": "M4bxrGZTQykEqOjq0WZ9cQKDhdatiPqCHV8GsZCdRSFn8bOXF4441q9vPzR/33ca9xePha+zhCw=",
                    "x-amz-request-id": "EPFRBXATAM2JCGDP",
                    "date": "Wed, 27 Jan 2021 14:51:32 GMT",
                    "content-type": "application/json",
                    "content-length": "637",
                    "server": "AmazonS3",
                },
                "RetryAttempts": 0,
            },
            "Policy": '{"Version":"2012-10-17","Statement":[{"Sid":"AWSCloudTrailAclCheck20150319","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::remediation-cloudtrail"},{"Sid":"AllowPublicReadAccess","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::remediation-cloudtrail/*"},{"Sid":"AWSCloudTrailWrite20150319","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::remediation-cloudtrail/AWSLogs/159636093902/*","Condition":{"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control"}}},{"Sid":"PublicRead","Effect":"Allow","Principal":{"AWS":"*"},"Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":"arn:aws:s3:::remediation-cloudtrail/*"}]}',
        }

        assert (
            action.remediate(
                cloudtrail_client,
                client,
                "cloudtrail_name",
                "region",
                "cloud_account_id",
            )
            == 0
        )
        assert client.put_public_access_block.call_count == 1
        assert client.get_bucket_policy_status.call_count == 1
        assert client.get_bucket_policy.call_count == 1
        assert client.put_bucket_policy.call_count == 1

        call_args = client.put_public_access_block.call_args
        updated_public_access_config = call_args[1]["PublicAccessBlockConfiguration"]
        assert updated_public_access_config == {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
        call_args_bucket_policy = client.put_bucket_policy.call_args
        updated_bucket_policy = call_args_bucket_policy[1]["Policy"]
        print(updated_bucket_policy)
        assert (
            updated_bucket_policy
            == '{"Version": "2012-10-17", "Statement": [{"Sid": "AWSCloudTrailAclCheck20150319", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:GetBucketAcl", "Resource": "arn:aws:s3:::remediation-cloudtrail"}, {"Sid": "AWSCloudTrailWrite20150319", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:PutObject", "Resource": "arn:aws:s3:::remediation-cloudtrail/AWSLogs/159636093902/*", "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}}]}'
        )

    def test_remediate_success_without_bucket_policy_public(self):
        client = Mock()
        cloudtrail_client = Mock()
        action = CloudtrailS3RemovePublicAccess()
        trail = {
            "Trail": {
                "Name": "CloudTrail_name",
                "S3BucketName": "remediation-cloudtrail",
            }
        }
        cloudtrail_client.get_trail.return_value = trail
        bucket_status = {
            "ResponseMetadata": {
                "RequestId": "9B28R8BGSR67A459",
                "HostId": "aS/3JTmp+hjghfjxfhc4VznkMTTkjhbjkKMCs93cfTCcC6R2rE3SIVziHRDFg=",
                "HTTPStatusCode": 200,
                "HTTPHeaders": {
                    "x-amz-id-2": "aS/3JTmp+hjghfjxfhc4VznkMTTkjhbjkKMCs93cfTCcC6R2rE3SIVziHRDFg=",
                    "x-amz-request-id": "9B28R8BGSR67A459",
                    "date": "Wed, 27 Jan 2021 14:51:32 GMT",
                    "transfer-encoding": "chunked",
                    "server": "AmazonS3",
                },
                "RetryAttempts": 0,
            },
            "PolicyStatus": {"IsPublic": False},
        }
        client.get_bucket_policy_status.return_value = bucket_status

        assert (
            action.remediate(
                cloudtrail_client,
                client,
                "cloudtrail_name",
                "region",
                "cloud_account_id",
            )
            == 0
        )
        assert client.put_public_access_block.call_count == 1
        assert client.get_bucket_policy_status.call_count == 1

        call_args = client.put_public_access_block.call_args
        updated_public_access_config = call_args[1]["PublicAccessBlockConfiguration"]
        assert updated_public_access_config == {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }

    def test_remediate_with_exception(self):
        class TestClient(object):
            def put_public_access_block(self, **kwargs):
                raise ClientError(
                    {
                        "Error": {
                            "Code": "NotFound",
                            "Message": "InvalidPermission.NotFound",
                        }
                    },
                    "TestCloudtrailS3PublicAccess",
                )

        client = TestClient()
        action = CloudtrailS3RemovePublicAccess()
        with pytest.raises(Exception):
            assert action.remediate(client, "bucket_name", "cloud_account_id")
