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


class EnableKmsKeyRotation(object):
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
        key_id = finding_info.get("ObjectId", None)

        object_chain = remediation_entry["notificationInfo"]["FindingInfo"][
            "ObjectChain"
        ]
        object_chain_dict = json.loads(object_chain)
        cloud_account_id = object_chain_dict["cloudAccountId"]
        region = finding_info.get("Region")

        logging.info(f"cloud_account_id: {cloud_account_id}")
        logging.info(f"region: {region}")

        if key_id is None:
            raise Exception(
                "Missing parameters for 'payload.notificationInfo.ObjectId'."
            )

        logging.info("parsed params")
        logging.info(f"  key_id: {key_id}")

        return_dict = {
            "region": region,
            "key_id": key_id,
        }
        logging.info(return_dict)
        return return_dict

    def remediate(self, kms_client, key_id, region):
        """Encrypts Cloudtrail Logs
        :param region: The region in which the key exists.
        :param kms_client: Instance of the AWS boto3 client.
        :param key_name: Name of the Cloudtrail.
        :type region: str.
        :type kms_client: object.
        :type key_id: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """
        try:
            logging.info(f"Enabling Rotation for the KMS key {key_id}")
            logging.info("executing client.enable_key_rotation")
            kms_client.enable_key_rotation(KeyId=key_id)
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
        logging.info("acquired kms client and parsed params - starting remediation")
        rc = self.remediate(kms_client=kms_client, **params)
        return rc


if __name__ == "__main__":
    logging.info("aws_kms_key_rotates.py called - running now")
    obj = EnableKmsKeyRotation()
    obj.run(sys.argv)
