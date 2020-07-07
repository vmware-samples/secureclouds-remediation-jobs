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

from botocore.exceptions import ClientError

class SecurityGroupClosePort3389(object):
    def parse(self, payload):
        """Parse payload received from Remediation Service.

        :param payload: JSON string containing parameters received from the remediation service.
        :type payload: str.
        :returns: Dictionary of parsed parameters
        :rtype: dict
        :raises: Exception, JSONDecodeError
        """
        remediation_entry = json.loads(payload)
        notification_info = remediation_entry.get("notificationInfo", None)

        finding_info = notification_info.get("FindingInfo", None)
        security_group_id = finding_info.get("ObjectId", None)

        if security_group_id is None:
            logging.error("Missing parameters for 'payload.notificationInfo.ObjectId'.")
            raise Exception(
                "Missing parameters for 'payload.notificationInfo.ObjectId'."
            )

        region = finding_info.get("Region", None)
        if region is None:
            logging.warning("no region specified - defaulting to us-east-1")
            region = "us-east-1"

        logging.info('parsed params')
        logging.info(f"  security_group_id: {security_group_id}")
        logging.info(f"  region: {region}")

        return {"security_group_id": security_group_id}, region

    def remediate(self, client, security_group_id):
        """Block public access to port 3389 for both IPv4 and IPv6.

        :param client: Instance of the AWS boto3 client.
        :param security_group_id: The ID of the security group. You must specify either the security group ID or the
            security group name in the request. For security groups in a nondefault VPC, you must specify the security
            group ID.
        :type security_group_id: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """

        # Revoke ipv4 permission
        logging.info('revoking ivp4 permissions')
        port = 3389
        try:
            logging.info('    executing client.revoke_security_group_ingress')
            logging.info('      CidrIp="0.0.0.0/0"')
            logging.info(f"      FromPort={port}")
            logging.info(f"      GroupId={security_group_id}")
            logging.info('      IpProtocol="tcp"')
            logging.info(f"      ToPort={port}")
            client.revoke_security_group_ingress(
                CidrIp="0.0.0.0/0",
                FromPort=port,
                GroupId=security_group_id,
                IpProtocol="tcp",
                ToPort=port,
            )
        except ClientError as e:
            if 'InvalidPermission.NotFound' not in str(e):
                logging.error(f"{str(e)}")
                raise

        # Revoke ipv6 permission
        logging.info('revoking ivp6 permissions')
        try:
            logging.info('    executing client.revoke_security_group_ingress')
            logging.info(f"      FromPort={port}")
            logging.info(f"      GroupId={security_group_id}")
            logging.info('      IpProtocol="tcp"')
            logging.info('      "Ipv6Ranges": [{"CidrIpv6": "::/0"}]')
            logging.info(f"      ToPort={port}")
            client.revoke_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[
                    {
                        "FromPort": port,
                        "IpProtocol": "tcp",
                        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                        "ToPort": port,
                    },
                ],
            )
        except ClientError as e:
            if 'InvalidPermission.NotFound' not in str(e):
                logging.error(f"{str(e)}")
                raise

        logging.info('successfully executed remediation')

        return 0

    def run(self, args):
        """Run the remediation job.

        :param args: List of arguments provided to the job.
        :type args: list.
        :returns: int
        """
        params, region = self.parse(args[1])
        client = boto3.client("ec2", region_name=region)
        logging.info('acquired ec2 client and parsed params - starting remediation')
        rc = self.remediate(client=client, **params)
        return rc


if __name__ == "__main__":
    logging.info('security_group_close_port_3389.py called - running now')
    obj = SecurityGroupClosePort3389()
    obj.run(sys.argv)
