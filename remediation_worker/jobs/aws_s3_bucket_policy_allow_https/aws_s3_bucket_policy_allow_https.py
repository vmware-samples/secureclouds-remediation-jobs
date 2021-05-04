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

from __future__ import annotations
from botocore.exceptions import ClientError

import json
import logging
import sys

import boto3

logging.basicConfig(level=logging.INFO)


class S3AllowOnlyHttpsRequest:
    def parse(self, payload):
        """Parse payload received from Remediation Service.

        :param payload: JSON string containing parameters sent to the remediation job.
        :type payload: str.
        :returns: Dictionary of parsed parameters
        :rtype: dict
        :raises: Exception, JSONDecodeError
        """
        remediation_entry = json.loads(payload)
        notification_info = remediation_entry.get("notificationInfo", None)
        finding_info = notification_info.get("FindingInfo", None)
        bucket_name = finding_info.get("ObjectId", None)
        object_chain = remediation_entry["notificationInfo"]["FindingInfo"][
            "ObjectChain"
        ]
        object_chain_dict = json.loads(object_chain)
        cloud_account_id = object_chain_dict["cloudAccountId"]

        if bucket_name is None:
            logging.error("Missing parameters for 'BUCKET_NAME'.")
            raise Exception("Missing parameters for 'BUCKET_NAME'.")

        logging.info("parsed params")
        logging.info(f"  bucket_name: {bucket_name}")
        logging.info(f"cloud_account_id: {cloud_account_id}")

        return {
            "cloud_account_id": cloud_account_id,
            "bucket_name": bucket_name,
        }

    def get_policy(self, client, bucket_name, cloud_account_id):
        """Getting Bucket Ploicy
        :param client: Instance of the AWS boto3 client.
        :param cloud_account_id: AWS Account Id.
        :param bucket_name: Name of the bucket.
        :type cloud_account_id: str.
        :type bucket_name: str.
        :returns: Bucket Policy
        :rtype: dict
        :raises: botocore.exceptions.ClientError
        """
        try:
            logging.info("making api call to client.get_bucket_policy")
            logging.info(f"Bucket_name: {bucket_name}")
            policy = {}
            bucket_policy = client.get_bucket_policy(
                Bucket=bucket_name, ExpectedBucketOwner=cloud_account_id,
            )
            policy = json.loads(bucket_policy["Policy"])
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return policy
            else:
                raise e
        return policy

    def remediate(self, client, cloud_account_id, bucket_name):
        """Configuring S3 bucket policy to deny unsecured HTTP traffic.

        :param client: Instance of the AWS boto3 client.
        :param cloud_account_id: AWS Account Id.
        :param bucket_name: Name of the bucket.
        :type cloud_account_id: str.
        :type bucket_name: str.
        :returns: Integer signaling success or failure.
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """

        try:
            policy = self.get_policy(client, bucket_name, cloud_account_id)
            # Policy Statement to restrict http requests
            restrict_http = {
                "Sid": "Restrict Non-https Requests",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }
            if policy:
                # If the Bucket Policy is present
                statements = policy["Statement"]
                statements.append(restrict_http)
            else:
                # If the Bucket Policy does not present
                policy = {"Version": "2012-10-17", "Statement": [restrict_http]}
            logging.info("making api call to client.put_bucket_policy")
            logging.info(f"Bucket_name: {bucket_name}")
            client.put_bucket_policy(
                Bucket=bucket_name,
                Policy=json.dumps(policy),
                ExpectedBucketOwner=cloud_account_id,
            )
            logging.info(f"successfully executed remediation for bucket: {bucket_name}")
        except Exception as e:
            logging.error(f"{str(e)}")
            raise
        return 0

    def run(self, args):
        """Run the remediation job.

        :param args: List of arguments provided to the job.
        :type args: list.
        :returns: int
        """
        params = self.parse(args[1])
        client = boto3.client("s3")
        logging.info("acquired s3 client and parsed params - starting remediation")
        rc = self.remediate(client=client, **params)
        return rc


if __name__ == "__main__":
    logging.info("aws_s3_bucket_policy_allow_https.py called - running now")
    obj = S3AllowOnlyHttpsRequest()
    obj.run(sys.argv)
