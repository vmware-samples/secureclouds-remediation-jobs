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


class InactiveRootAccessKeys(object):
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
        root_user_name = finding_info.get("ObjectId", None)

        if root_user_name is None:
            raise Exception(
                "Missing parameters for 'payload.notificationInfo.ObjectId'."
            )

        logging.info("parsed params")
        logging.info(f"  root_user_name: {root_user_name}")

        return_dict = {
            "root_user_name": root_user_name,
        }
        logging.info(return_dict)
        return return_dict

    def remediate(self, client, root_user_name):
        """Making the root user access keys inactive
        :param client: Instance of the AWS boto3 client.
        :param root_user_name: IAM root User.
        :type client: object.
        :type root_user_name: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """
        try:
            logging.info("Making the root user access keys inactive")
            logging.info("executing client.list_access_keys")
            access_keys = client.list_access_keys(UserName=root_user_name)
            for access_key in access_keys["AccessKeyMetadata"]:
                if access_key["Status"] == "Active":
                    logging.info("executing client.update_access_key")
                    client.update_access_key(
                        UserName=root_user_name,
                        AccessKeyId=access_key["AccessKeyId"],
                        Status="Inactive",
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
        client = boto3.client("iam")
        logging.info("acquired iam client and parsed params - starting remediation")
        rc = self.remediate(client=client, **params)
        return rc


if __name__ == "__main__":
    logging.info("aws_iam_root_user_disable_access_keys.py called - running now")
    obj = InactiveRootAccessKeys()
    obj.run(sys.argv)
