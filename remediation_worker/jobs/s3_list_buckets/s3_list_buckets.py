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

class S3ListBuckets:
    def parse(self, payload):
        """Parse payload received from Remediation Service.

        :param payload: JSON string containing parameters sent to the remediation job.
        :type payload: str.
        :returns: Dictionary of parsed parameters
        :rtype: dict
        :raises: Exception, IndexError, JSONDecodeError
        """
        remediation_entry = json.loads(payload)

        logging.info('parsed params')
        logging.info(f"  remediation_entry: {remediation_entry}")


        return {}

    def remediate(self, client, **kwargs):
        """List S3 bucket.

        :param client: Instance of the AWS boto3 client.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """

        response = client.list_buckets()
        for bucket in response["Buckets"]:
            logging.info(f"  bucket: {bucket['Name']}")
        logging.info('successfully executed s3-list-buckets')

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
    logging.info('s3_list_buckets.py called - running now')
    obj = S3ListBuckets()
    obj.run(sys.argv)
