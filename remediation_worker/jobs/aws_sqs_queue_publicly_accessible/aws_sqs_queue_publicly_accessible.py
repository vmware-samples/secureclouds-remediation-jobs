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


class SqsQueuePubliclyAccessible:
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
        queue_name = finding_info.get("ObjectId", None)
        object_chain = remediation_entry["notificationInfo"]["FindingInfo"][
            "ObjectChain"
        ]
        object_chain_dict = json.loads(object_chain)
        cloud_account_id = object_chain_dict["cloudAccountId"]
        region = finding_info.get("Region")

        if queue_name is None:
            logging.error("Missing parameters for 'SQS_QUEUE_NAME'.")
            raise Exception("Missing parameters for 'SQS_QUEUE_NAME'.")

        logging.info("parsed params")
        logging.info(f"  region: {region}")
        logging.info(f"cloud_account_id: {cloud_account_id}")
        logging.info(f"  queue_name: {queue_name}")

        return {
            "region": region,
            "cloud_account_id": cloud_account_id,
            "queue_name": queue_name,
        }

    def remediate(self, client, region, cloud_account_id, queue_name):
        """Remove SQS Queue Policy Statement that allows public access
        :param client: Instance of the AWS boto3 client.
        :param region: Region in which the SQS Queue exists
        :param cloud_account_id: AWS Account Id.
        :param queue_name: Name of the SQS Queue.
        :type cloud_account_id: str.
        :type queue_name: str.
        :type region: str.
        :returns: Integer signaling success or failure.
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """

        try:
            logging.info("making api call to client.get_queue_url")
            logging.info(f"Queue_name: {queue_name}")
            queue_url_response = client.get_queue_url(
                QueueName=queue_name, QueueOwnerAWSAccountId=cloud_account_id,
            )
            queue_url = queue_url_response["QueueUrl"]

            # Get the queue policy
            logging.info("making api call to client.get_queue_attributes")
            queue_attributes = client.get_queue_attributes(
                QueueUrl=queue_url, AttributeNames=["Policy"],
            )

            queue_policy = json.loads(queue_attributes["Attributes"]["Policy"])

            for statement in queue_policy["Statement"]:
                if (
                    statement["Effect"] == "Allow"
                    and "Condition" not in statement
                    and statement["Principal"] in ["*", {"AWS": "*"}]
                ):
                    logging.info("making api call to client.remove_permission")
                    # Removing those policy statements from the Queue that allow public access
                    client.remove_permission(QueueUrl=queue_url, Label=statement["Sid"])
            logging.info(f"successfully executed remediation for Queue: {queue_name}")
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
        client = boto3.client("sqs", params["region"])
        logging.info("acquired sqs client and parsed params - starting remediation")
        rc = self.remediate(client=client, **params)
        return rc


if __name__ == "__main__":
    logging.info("aws_sqs_queue_publicly_accessible.py called - running now")
    obj = SqsQueuePubliclyAccessible()
    obj.run(sys.argv)
