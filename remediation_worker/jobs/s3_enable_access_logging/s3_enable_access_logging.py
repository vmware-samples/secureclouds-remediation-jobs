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

import copy
import json
import logging
import sys

import boto3

logging.basicConfig(level=logging.INFO)


class SelfRemediationError(ValueError):
    pass


class S3EnableAccessLogging(object):
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
        source_bucket = finding_info.get("ObjectId", None)

        object_chain = remediation_entry["notificationInfo"]["FindingInfo"][
            "ObjectChain"
        ]
        object_chain_dict = json.loads(object_chain)
        cloud_account_id = object_chain_dict["cloudAccountId"]
        region = finding_info.get("Region")

        logging.info(f"cloud_account_id: {cloud_account_id}")
        logging.info(f"region: {region}")

        target_bucket = f"vss-logging-target-{cloud_account_id}-{region}"

        if source_bucket is None:
            raise Exception(
                "Missing parameters for 'payload.notificationInfo.ObjectId'."
            )

        logging.info("parsed params")
        logging.info(f"  source_bucket: {source_bucket}")

        target_prefix = source_bucket

        return_dict = {
            "region": region,
            "source_bucket": source_bucket,
            "target_bucket": target_bucket,
            "target_prefix": f"s3bucket/{target_prefix}",
        }
        logging.info(return_dict)
        return return_dict

    def check_log_delivery_permissions(self, acl):
        """Checks if the S3 bucket has log delivery permissions.
        :param acl: S3 bucket acl.
        :type acl: dict.
        :returns: Tuple which indicates if read and write permissions were granted.
        :rtype: tuple.
        """
        write_grant = False
        read_acp_grant = False

        grants = acl.get("Grants")

        if grants is None:
            return write_grant, read_acp_grant

        for grant in grants:
            grantee = grant.get("Grantee")
            if grantee is None:
                continue
            grantee_type = grantee.get("Type")
            grantee_uri = grantee.get("URI")
            if grantee_type is None or grantee_uri is None:
                continue
            if (
                grantee_type == "Group"
                and grantee_uri == "http://acs.amazonaws.com/groups/s3/LogDelivery"
            ):
                if grant["Permission"] == "WRITE":
                    write_grant = True
                elif grant["Permission"] == "READ_ACP":
                    read_acp_grant = True

        return write_grant, read_acp_grant

    def grant_log_delivery_permissions(self, client, bucket_name):
        """Give the group log-delievery WRITE and READ_ACP permisions to the target bucket.
        :param client: Instance of the AWS boto3 client.
        :bucket_name: Name of the bucket.
        :type client: object.
        :type bucket_name: str.
        :returns: None.
        :rtype: None.
        """
        acl = client.get_bucket_acl(Bucket=bucket_name)

        # check if the required permissions are already granted, and if present return
        write_granted, read_acp_granted = self.check_log_delivery_permissions(acl)
        if write_granted and read_acp_granted:
            return

        write_grant = {
            "Grantee": {
                "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                "Type": "Group",
            },
            "Permission": "WRITE",
        }
        read_acp_grant = {
            "Grantee": {
                "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                "Type": "Group",
            },
            "Permission": "READ_ACP",
        }
        del acl["ResponseMetadata"]

        modified_acl = copy.deepcopy(acl)
        if not write_granted:
            modified_acl["Grants"].append(write_grant)
        if not read_acp_granted:
            modified_acl["Grants"].append(read_acp_grant)
        client.put_bucket_acl(Bucket=bucket_name, AccessControlPolicy=modified_acl)

    def ensure_log_target_bucket(self, client, target_bucket, region):
        """Check if the log target bucket exists if not then creates one.
        :param client: Instance of the AWS boto3 client.
        :param target_bucket: Target bucket name.
        :param region:region in which the target bucket exists.
        :type client: object.
        :type target_bucket: str.
        :type region: str.
        :returns: None.
        :rtype: None.
        """
        try:
            print(target_bucket)
            client.head_bucket(Bucket=target_bucket)
        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                # The bucket does not exist
                if region == "us-east-1":
                    client.create_bucket(Bucket=target_bucket)
                else:
                    client.create_bucket(
                        Bucket=target_bucket,
                        CreateBucketConfiguration={"LocationConstraint": region},
                    )
                    self.encrypt_target_bucket(client, target_bucket)
            elif e.response["Error"]["Code"] == "403":
                # The assumed role does not have the permission
                logging.error("Not enough permissions to list buckets")
                raise e
            else:
                raise e

    def encrypt_target_bucket(self, client, bucket_name):
        """Encrypting the s3 bucket
        :param client: Instance of the AWS boto3 client.
        :param bucket_name: Name of the s3 bucket.
        :type client: object.
        :type bucket_name: str.
        :returns: None.
        :rtype: None.
        """
        client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        )

    def remediate(self, region, client, source_bucket, target_bucket, target_prefix):
        """Enable access logging for an S3 bucket.

        Logs are stored in :param:`target_bucket`.

        Amazon S3 Log Delivery group write permission must be granted on the bucket the access logs are saved to.

        :param region: The buckets region
        :param client: Instance of the AWS boto3 client.
        :param source_bucket: The name of the bucket for which to set the logging parameters.
        :param target_bucket: Specifies the bucket where you want Amazon S3 to store server access logs.
        :param target_prefix: A prefix for all log object keys. If you store log files from multiple Amazon S3
            buckets in a single bucket, you can use a prefix to distinguish which log files came from which bucket.
        :type region: str.
        :type client: object.
        :type source_bucket: str.
        :type target_bucket: str.
        :type target_prefix: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """

        if source_bucket == target_bucket:
            raise SelfRemediationError(
                f"Cannot remediate the logging bucket (i.e. write access logs to self). "
                f"Consider suppressing the violation for this bucket ({source_bucket})."
            )
        try:
            self.ensure_log_target_bucket(client, target_bucket, region)
            logging.info("ensuring logs can be delivered")
            self.grant_log_delivery_permissions(client, target_bucket)
            logging.info("making client.put_bucket_logging to enable logging")
            logging.info(
                f"  Bucket: {source_bucket} | TargetBucket: {target_bucket} | TargetPrefix: {target_prefix}"
            )
            client.put_bucket_logging(
                Bucket=source_bucket,
                BucketLoggingStatus={
                    "LoggingEnabled": {
                        "TargetBucket": target_bucket,
                        "TargetPrefix": f"{target_prefix}/",
                    }
                },
            )
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
        client = boto3.client("s3")
        logging.info("acquired s3 client and parsed params - starting remediation")
        rc = self.remediate(client=client, **params)
        return rc


if __name__ == "__main__":
    logging.info("s3_enable_access_logging.py called - running now")
    obj = S3EnableAccessLogging()
    obj.run(sys.argv)
