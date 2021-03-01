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


class RemoveAdministrationPortsPublicAccess(object):
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
        network_acl_id = finding_info.get("ObjectId", None)

        object_chain = remediation_entry["notificationInfo"]["FindingInfo"][
            "ObjectChain"
        ]
        object_chain_dict = json.loads(object_chain)
        cloud_account_id = object_chain_dict["cloudAccountId"]
        region = finding_info.get("Region")

        logging.info(f"cloud_account_id: {cloud_account_id}")
        logging.info(f"region: {region}")

        if network_acl_id is None:
            raise Exception(
                "Missing parameters for 'payload.notificationInfo.ObjectId'."
            )

        return_dict = {
            "network_acl_id": network_acl_id,
        }
        logging.info(return_dict)
        return return_dict

    def remediate(self, client, network_acl_id):
        """Remove all the network acl rules that provide public access to administration ports (22 and 3389)
        :param client: Instance of the AWS ec2 client.
        :param network_acl_id: Network ACL Id
        :type client: object.
        :type network_acl_id: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """
        try:
            logging.info("executing client.describe_network_acls to get network acl")
            network_acl = client.describe_network_acls(NetworkAclIds=[network_acl_id])
            network_acl_entries = network_acl["NetworkAcls"][0]
            for entry in network_acl_entries["Entries"]:
                if (
                    entry["Egress"] is False
                    and entry["RuleAction"] == "allow"
                    and entry["Protocol"] in ["6", "-1"]
                    and (
                        "PortRange" not in entry
                        or entry["PortRange"]
                        in [{"From": 3389, "To": 3389}, {"From": 22, "To": 22}]
                    )
                    and entry["CidrBlock"] == "0.0.0.0/0"
                ):
                    client.delete_network_acl_entry(
                        Egress=False,
                        NetworkAclId=network_acl_id,
                        RuleNumber=entry["RuleNumber"],
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
        client = boto3.client("ec2")
        logging.info("acquired ec2 client and parsed params - starting remediation")
        rc = self.remediate(client=client, **params)
        return rc


if __name__ == "__main__":
    logging.info("aws_ec2_administration_ports_ingress_allowed.py called - running now")
    obj = RemoveAdministrationPortsPublicAccess()
    obj.run(sys.argv)
