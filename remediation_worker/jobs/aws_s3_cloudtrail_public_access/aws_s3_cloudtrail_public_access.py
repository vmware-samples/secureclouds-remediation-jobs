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
        notification_info = remediation_entry.get("notificationInfo", None)
        finding_info = notification_info.get("FindingInfo", None)
        cloudtrail_name = finding_info.get("ObjectId", None)

        object_chain = remediation_entry["notificationInfo"]["FindingInfo"][
            "ObjectChain"
        ]
        object_chain_dict = json.loads(object_chain)
        cloud_account_id = object_chain_dict["cloudAccountId"]
        region = finding_info.get("Region")

        logging.info(f"cloud_account_id: {cloud_account_id}")
        logging.info(f"region: {region}")

        if cloudtrail_name is None:
            raise Exception(
                "Missing parameters for 'payload.notificationInfo.ObjectId'."
            )

        return_dict = {
            "region": region,
            "cloudtrail_name": cloudtrail_name,
            "cloud_account_id": cloud_account_id,
        }
        logging.info(return_dict)
        return return_dict

    def remediate(
        self, cloudtrail_client, client, cloudtrail_name, region, cloud_account_id
    ):
        """Block public access write bucket ACL
        :param client: Instance of the AWS boto3 client.
        :param bucket_name: The name of the bucket for which to block access.
        :type bucket_name: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """
        try:
            cloudtrail = cloudtrail_client.get_trail(Name=cloudtrail_name)
            bucket_name = cloudtrail["Trail"]["S3BucketName"]
            logging.info("making api call to client.put_public_access_block")
            logging.info(f"Bucket_name: {bucket_name}")
            # Blocking all users and authenticated users access from bucket acl
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

            # If the bucket policy status is public
            if status["IsPublic"] is True:
                logging.info("making api call to client.get_bucket_policy")
                logging.info(f"Bucket_name: {bucket_name}")
                bucket_policy = client.get_bucket_policy(
                    Bucket=bucket_name, ExpectedBucketOwner=cloud_account_id,
                )
                policy = json.loads(bucket_policy["Policy"])
                statements = policy["Statement"]
                # Remove the statements in which Principal is * or {"AWS":"*"} and effect is set to allow
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
        params = self.parse(args[1])
        cloudtrail_client = boto3.client("cloudtrail", params["region"])
        client = boto3.client("s3")
        logging.info(
            "acquired s3 client, cloudtrail_client and parsed params - starting remediation"
        )
        rc = self.remediate(
            cloudtrail_client=cloudtrail_client, client=client, **params
        )
        return rc


if __name__ == "__main__":
    logging.info("aws_s3_cloudtrail_public_access.py called - running now")
    obj = CloudtrailS3RemovePublicAcces()
    obj.run(sys.argv)
