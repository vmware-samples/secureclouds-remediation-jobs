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


class DeleteExpiredServerCertificate(object):
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
        certificate_name = finding_info.get("ObjectId", None)

        if certificate_name is None:
            raise Exception(
                "Missing parameters for 'payload.notificationInfo.ObjectId'."
            )

        logging.info("parsed params")
        logging.info(f"  certificate_name: {certificate_name}")

        return_dict = {
            "certificate_name": certificate_name,
        }
        logging.info(return_dict)
        return return_dict

    def remediate(self, client, certificate_name):
        """Deleting Expired Server Certificate
        :param client: Instance of the AWS boto3 client.
        :param certificate_name: Certificate name.
        :type client: object.
        :type certificate_name: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """
        try:
            logging.info(f"Deleting Expired Server Certificate: {certificate_name}")
            logging.info("executing client.delete_server_certificate")
            client.delete_server_certificate(ServerCertificateName=certificate_name)
            logging.info("successfully completed remediation job")
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
        client = boto3.client("iam")
        logging.info("acquired iam client and parsed params - starting remediation")
        rc = self.remediate(client=client, **params)
        return rc


if __name__ == "__main__":
    logging.info("aws_iam_server_certificate_expired.py called - running now")
    obj = DeleteExpiredServerCertificate()
    obj.run(sys.argv)
