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
import json
from botocore.exceptions import ClientError

from remediation_worker.jobs.elb_enable_access_logs.elb_enable_access_logs import create_or_update_bucket_policy

def ordered(o):
    """deeply order o"""
    if isinstance(o, dict):
        return frozenset((k, ordered(v)) for k, v in o.items())
    if isinstance(o, list):
        return frozenset(ordered(x) for x in o)
    else:
        return o

def policies_equal(a, b):
    return ordered(json.loads(a)) == ordered(json.loads(b))

class ExampleClient:
    def __init__(self, expected_policy):
        self.expected_policy = expected_policy

    def put_bucket_policy(self, *args, **kwargs):
        assert policies_equal(kwargs['Policy'], self.expected_policy)

@pytest.fixture
def test_data():
    bucket_name = 'vss-logging-target-650397460025-us-east-1'
    bucket_prefix = 'jackson-test-classic-elb'
    account_id = '650397460025'
    region = 'us-east-1'

    policy = """
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::127311923021:root"
                },
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::vss-logging-target-650397460025-us-east-1/jackson-test-classic-elb/AWSLogs/650397460025/*"
            }
        ]
    }
    """

    valid_policy = """
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::127311923021:root"
                },
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::vss-logging-target-650397460025-us-east-1/jackson-test-classic-elb/AWSLogs/650397460025/*"
            },
            {
                "Sid": "AddCannedAcl",
                "Effect": "Allow",
                "Principal": {"AWS": ["arn:aws:iam::111122223333:root", "arn:aws:iam::444455556666:root"]},
                "Action": ["s3:PutObject", "s3:PutObjectAcl"],
                "Resource": "arn:aws:s3:::awsexamplebucket1/*",
                "Condition": {"StringEquals": {"s3:x-amz-acl": ["public-read"]}}
            }
        ]
    }
    """

    invalid_policy = """
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AddCannedAcl",
                "Effect": "Allow",
                "Principal": {"AWS": ["arn:aws:iam::111122223333:root", "arn:aws:iam::444455556666:root"]},
                "Action": ["s3:PutObject", "s3:PutObjectAcl"],
                "Resource": "arn:aws:s3:::awsexamplebucket1/*",
                "Condition": {"StringEquals": {"s3:x-amz-acl": ["public-read"]}}
            }
        ]
    }
    """

    return locals()

class TestCreateOrUpdateBucketPolicy:
    def test_no_policy(self, test_data):
        class NoPolicyClient(ExampleClient):
            def get_bucket_policy(self, *args, **kwargs):
                raise ClientError({'Error': {'Code': 'NoSuchBucketPolicy'}}, None)

        client = NoPolicyClient(test_data['policy'])
        create_or_update_bucket_policy(client, test_data['bucket_name'], test_data['bucket_prefix'], test_data['account_id'], test_data['region'])

    def test_valid_policy(self, test_data):
        class ValidPolicyClient(ExampleClient):
            def get_bucket_policy(self, *args, **kwargs):
                return {'Policy': self.expected_policy}

            def put_bucket_policy(self, *args, **kwargs):
                raise Exception('should not call put_bucket_policy if the policy is already valid')

        client = ValidPolicyClient(test_data['valid_policy'])
        create_or_update_bucket_policy(client, test_data['bucket_name'], test_data['bucket_prefix'], test_data['account_id'], test_data['region'])

    def test_invalid_policy(self, test_data):
        class InvalidPolicyClient(ExampleClient):
            def get_bucket_policy(self, *args, **kwargs):
                return {'Policy': test_data['invalid_policy']}

        client = InvalidPolicyClient(test_data['valid_policy'])
        create_or_update_bucket_policy(client, test_data['bucket_name'], test_data['bucket_prefix'], test_data['account_id'], test_data['region'])
