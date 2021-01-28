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

import json
import logging
import sys
import boto3

logging.basicConfig(level=logging.INFO)


class CloudtrailS3RemovePublicAcces:
    def parse(self, payload):
        """Parse payload received from Remediation Service.
        :param payload: JSON string containing parameters sent to the remediation job.
        :type payload: str.
        :returns: Dictionary of parsed parameters
        :rtype: dict
        :raises: Exception, JSONDecodeError
        """
        remediation_entry = json.loads(payload)
        object_chain = remediation_entry["notificationInfo"]["FindingInfo"][
            "ObjectChain"
        ]
        object_chain_dict = json.loads(object_chain)
        cloud_account = object_chain_dict["cloudAccountId"]
        properties = object_chain_dict["properties"]
        S3bucket_name = ""

        for property in properties:
            if property["name"] == "S3BucketName" and property["type"] == "string":
                S3bucket_name = property["stringV"]
                break

        logging.info("parsed params")
        logging.info(f"  bucket_name: {S3bucket_name}")
        logging.info(f"  cloud_account_id: {cloud_account}")

        return {
            "bucket_name": S3bucket_name,
            "cloud_account_id": cloud_account,
        }

    def remediate(self, client, bucket_name, cloud_account_id):
        """Block public access write bucket ACL
        :param client: Instance of the AWS boto3 client.
        :param bucket_name: The name of the bucket for which to block access.
        :type bucket_name: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """
        try:
            logging.info("making api call to client.put_public_access_block")
            logging.info(f"Bucket_name: {bucket_name}")
            client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )

            logging.info("making api call to client.put_bucket_policy_status")
            logging.info(f"Bucket_name: {bucket_name}")
            bucket_policy_status = client.get_bucket_policy_status(
                Bucket=bucket_name, ExpectedBucketOwner=cloud_account_id,
            )
            status = bucket_policy_status["PolicyStatus"]
            logging.info(f"Bucket_policy_status: {status}")

            if status["IsPublic"] is True:
                logging.info("making api call to client.get_bucket_policy")
                logging.info(f"Bucket_name: {bucket_name}")
                bucket_policy = client.get_bucket_policy(
                    Bucket=bucket_name, ExpectedBucketOwner=cloud_account_id,
                )
                policy = json.loads(bucket_policy["Policy"])
                statements = policy["Statement"]
                for statement in statements:
                    if statement["Effect"] == "Allow" and statement["Principal"] in (
                        {"AWS": "*"},
                        "*",
                    ):
                        statements.remove(statement)

                logging.info("making api call to client.put_bucket_policy")
                logging.info(f"Bucket_name: {bucket_name}")
                client.put_bucket_policy(
                    Bucket=bucket_name,
                    Policy=json.dumps(policy),
                    ExpectedBucketOwner=cloud_account_id,
                )
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
        client = boto3.client("s3")
        params = self.parse(args[1])
        logging.info("acquired s3 client and parsed params - starting remediation")
        rc = self.remediate(client=client, **params)
        return rc


if __name__ == "__main__":
    logging.info("s3_remove_public_access.py called - running now")
    obj = CloudtrailS3RemovePublicAcces()
    obj.run(sys.argv)
