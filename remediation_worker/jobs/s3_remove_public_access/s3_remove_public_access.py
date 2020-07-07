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

import boto3
import json
import sys
import logging
logging.basicConfig(level=logging.INFO)

class S3RemovePublicAccess:
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

        if bucket_name is None:
            logging.error("Missing parameters for 'BUCKET_NAME'.")
            raise Exception("Missing parameters for 'BUCKET_NAME'.")

        logging.info('parsed params')
        logging.info(f"  bucket_name: {bucket_name}")

        return {"bucket_name": bucket_name}

    def remediate(self, client, bucket_name):
        """Block public access to an S3 bucket.

        :param client: Instance of the AWS boto3 client.
        :param bucket_name: The name of the bucket for which to block access.
        :type bucket_name: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """

        logging.info('making api call to client.put_public_access_block')
        client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        logging.info(f"successfully executed remediation for bucket: {bucket_name}")
        return 0

    def run(self, args):
        """Run the remediation job.

        :param args: List of arguments provided to the job.
        :type args: list.
        :returns: int
        """
        client = boto3.client("s3")
        params = self.parse(args[1])
        logging.info('acquired s3 client and parsed params - starting remediation')
        rc = self.remediate(client=client, **params)
        return rc


if __name__ == "__main__":
    logging.info('s3_remove_public_access.py called - running now')
    obj = S3RemovePublicAccess()
    obj.run(sys.argv)
