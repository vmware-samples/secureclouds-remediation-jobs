# Copyright (c) 2021 VMware Inc.
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
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO)


class KinesisEncryptStream():
    def parse(self, payload):
        """Parse payload received from Remediation Service.
        Args:
            payload: (str) JSON string containing parameters
                    received from the remediation service.
        Raises:
            Exception: JSONDecodeError
        Returns:
            (dict) Dictionary of parsed parameters.
        """
        remediation_entry = json.loads(payload)
        notification_info = remediation_entry.get("notificationInfo", None)
        finding_info = notification_info.get("FindingInfo", None)

        stream_name = finding_info.get("ObjectId", None)
        region = finding_info.get("Region", None)

        if stream_name is None:
            logging.error("Missing parameters for 'STREAM_NAME'.")
            raise Exception("Missing parameters for 'stream_name'.")

        if region is None:
            logging.error("Missing parameters for 'REGION'.")
            raise Exception("Missing parameters for 'REGION'.")

        logging.info("parsed params:")
        logging.info("  stream_name: %s", stream_name)
        logging.info("  region: %s", region)

        return {
            "stream_name": stream_name,
            "region": region
        }

    def remediate(self, stream_name, client, region):
        """Encrypts unencrypted kinesis data streams.
        Args:
            stream_name ([str]): The name of the kinesis stream.
            client: Instance of the AWS boto3 client.
        """

        logging.info(
            "Beginning kinesis data stream encryption evaluation."
        )

        # Check to see if kinesis data stream is encrypted
        encryption_type = self.check_encryption(client, stream_name)

        # If kinesis data stream is not encrypted
        if encryption_type == "NONE":
            res = self.enable_encryption(client, stream_name)
            return res 
        # If encryption is enabled
        # We have nothing to do.
        # log and exit
        elif encryption_type == "KMS":
            logging.info(
                "Kinesis data stream %s is already encrypted, taking no action.",
                stream_name
            )
            return 0
        # If anything else returns,
        # log and exit
        else:
            error = "An unknown encryption type {0} returned for kinesis data stream {1}. Exiting".format(encryption_type, stream_name) 
            logging.error(error)
            return 1

    def check_encryption(self, client, stream_name):
        """Checks the kinesis data stream encryption setting.
        Args:
            client: Instance of the AWS boto3 client
            stream_name ([str]): The name of the kinesis stream.
        Returns:
            [string]: "NONE" if no encryption is enabled.
        """

        # Check if stream is encrypted
        try:
            encryption_type = client.describe_stream(
                StreamName=stream_name)["StreamDescription"]["EncryptionType"]
            return encryption_type

        except ClientError as user_error:          
            if user_error.response["Error"]["Code"] == "ResourceNotFoundException":
                logging.error(
                "A failure occured with error: %s. Check if the resource exists.", user_error.response['Error']['Code']
            )
            elif user_error.response["Error"]["Code"] == "LimitExceededException":
                error = "Receiving LimitExceededException exception: {0} while trying to encrypt kinesis data stream {1}".format(stream_name,user_error.response["Error"]["Code"]) 
                logging.error(error)
            
        
        except Exception as e:
            error = "Receiving other exceptions {0} reading kinesis data stream {1}".format(str(e), stream_name)
            logging.error(error)

        return ""

    def enable_encryption(self, client, stream_name):
        """Enable encryption on the kinesis data stream.
        Args:
            client: Instance of the AWS boto3 client.
            stream_name ([str]): The name of the kinesis stream.
        """
        logging.info(
            "Enabling encryption on kinesis data stream %s",
            stream_name
        )
        try:
            client.start_stream_encryption(
                StreamName=stream_name,
                EncryptionType="KMS",
                KeyId="alias/aws/kinesis"  # KEK owned by Kinesis Data Streams
            )
            logging.info(
                "Encryption enabled on kinesis data stream %s",
                stream_name
            )
            return 0
        except ClientError as user_error:
            if user_error.response["Error"]["Code"] == "ResourceInUseException":
                logging.error(
                    "Kinesis data stream %s is in an unavailable state.",
                    stream_name
                )
            else:
               error = "Receiving Kinesis exception: {0} while tyring to encrypt kinesis data stream {1}".format(stream_name,user_error.response["Error"]["Code"]) 
               logging.error(error)
            return 1
        except Exception as e:
            error = "Receiving exception {0} for kinesis data stream {1}".format(str(e), stream_name)
            logging.error(error)
            return 1


    def run(self, args):
        """Run the remediation job.
        Args:
            args ([list]): List of arguments provided to the job.
        Returns:
            [int]
        """

        params = self.parse(args[1])
        client = boto3.client("kinesis", region_name=params['region'])

        logging.info(
            "Acquired kinesis client and parsed params - starting remediation."
        )

        return self.remediate(client=client, **params)


if __name__ == "__main__":
    logging.info(
        "kinesis_encrypt_stream.py called - running now %s",
        sys.argv[0]
    )
    obj = KinesisEncryptStream()
    obj.run(sys.argv)
