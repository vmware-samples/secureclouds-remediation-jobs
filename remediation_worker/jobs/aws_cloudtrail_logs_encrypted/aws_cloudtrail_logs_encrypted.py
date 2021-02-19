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


class CloudtrailEncryptLogs(object):
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

        logging.info("parsed params")
        logging.info(f"  cloudtrail_name: {cloudtrail_name}")

        return_dict = {
            "cloud_account_id": cloud_account_id,
            "region": region,
            "cloudtrail_name": cloudtrail_name,
        }
        logging.info(return_dict)
        return return_dict

    def create_key(self, cloud_account_id, kms_client):
        """Creates a key
        :param cloud_account_id: AWS Account Id
        :param kms_client: Instance of the AWS boto3 client
        :type cloud_account_id: str
        :type kms_client: object
        :returns: Key Id
        :rtype: str
        """
        key_policy = {
            "Version": "2012-10-17",
            "Id": "Key policy created by CloudTrail",
            "Statement": [
                {
                    "Sid": "Enable IAM User Permissions",
                    "Effect": "Allow",
                    "Principal": {"AWS": [f"arn:aws:iam::{cloud_account_id}:root"]},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "Allow CloudTrail to encrypt logs",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "kms:GenerateDataKey*",
                    "Resource": "*",
                    "Condition": {
                        "StringLike": {
                            "kms:EncryptionContext:aws:cloudtrail:arn": f"arn:aws:cloudtrail:*:{cloud_account_id}:trail/*"
                        }
                    },
                },
                {
                    "Sid": "Allow CloudTrail to describe key",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "kms:DescribeKey",
                    "Resource": "*",
                },
                {
                    "Sid": "Allow principals in the account to decrypt log files",
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": ["kms:Decrypt", "kms:ReEncryptFrom"],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"kms:CallerAccount": cloud_account_id},
                        "StringLike": {
                            "kms:EncryptionContext:aws:cloudtrail:arn": f"arn:aws:cloudtrail:*:{cloud_account_id}:trail/*"
                        },
                    },
                },
                {
                    "Sid": "Enable cross account log decryption",
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": ["kms:Decrypt", "kms:ReEncryptFrom"],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"kms:CallerAccount": cloud_account_id},
                        "StringLike": {
                            "kms:EncryptionContext:aws:cloudtrail:arn": f"arn:aws:cloudtrail:*:{cloud_account_id}:trail/*"
                        },
                    },
                },
            ],
        }
        new_key_policy = json.dumps(key_policy)
        key = kms_client.create_key(
            Policy=new_key_policy,
            Description="Encrypts Cloudtrail",
            KeyUsage="ENCRYPT_DECRYPT",
            CustomerMasterKeySpec="SYMMETRIC_DEFAULT",
            Origin="AWS_KMS",
            BypassPolicyLockoutSafetyCheck=False,
            Tags=[{"TagKey": "Created By", "TagValue": "CHSS"},],
        )
        kms_client.enable_key_rotation(KeyId=key["KeyMetadata"]["KeyId"])
        return key["KeyMetadata"]["KeyId"]

    def remediate(
        self, region, kms_client, cloudtrail_client, cloudtrail_name, cloud_account_id
    ):
        """Encrypts Cloudtrail Logs
        :param region: The buckets region
        :param kms_client: Instance of the AWS boto3 client.
        :param cloudtrail_client: Instance of the AWS boto3 client.
        :param cloudtrail_name: Name of the Cloudtrail.
        :param cloud_account_id: AWS Account Id.
        :type region: str.
        :type kms_client: object.
        :type cloudtrail_client: object.
        :type cloud_account_id: str.
        :type cloudtrail_name: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """
        try:
            logging.info("Creating an AWS Symmetric CMK")
            key_id = self.create_key(cloud_account_id, kms_client)

            logging.info("Encrypting the Cloudtrail logs")
            logging.info("executing cloudtrail_client.update_trail")
            logging.info(f"Name = {cloudtrail_name}")
            logging.info(f"KmsKeyId = {key_id}")
            cloudtrail_client.update_trail(
                Name=cloudtrail_name, KmsKeyId=key_id,
            )
            logging.info("successfully completed remediation job")
        except Exception as e:
            logging.error(f"{str(e)}")
        return 0

    def run(self, args):
        """Run the remediation job.

        :param args: List of arguments provided to the job.
        :type args: list.
        :returns: int
        """
        params = self.parse(args[1])
        kms_client = boto3.client("kms", region_name=params["region"])
        cloudtrail_client = boto3.client("cloudtrail", region_name=params["region"])
        logging.info(
            "acquired kms client, cloudtrail client and parsed params - starting remediation"
        )
        rc = self.remediate(
            kms_client=kms_client, cloudtrail_client=cloudtrail_client, **params
        )
        return rc


if __name__ == "__main__":
    logging.info("aws_cloudtrail_logs_encrypted.py called - running now")
    obj = CloudtrailEncryptLogs()
    obj.run(sys.argv)
