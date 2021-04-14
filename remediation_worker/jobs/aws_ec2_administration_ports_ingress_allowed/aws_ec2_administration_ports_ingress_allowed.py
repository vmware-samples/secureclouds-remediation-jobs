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
            "cloud_account_id": cloud_account_id,
            "region": region,
            "network_acl_id": network_acl_id,
        }
        logging.info(return_dict)
        return return_dict

    def create_list_of_rule_nos(self, network_acl_id, client):
        """Creates List of Rule Numbers in the Network Acl
        :param network_acl_id: Network Acl Id.
        :param client: Instance of the AWS boto3 client.
        :type network_acl_id: str.
        :type client: object
        :returns: List of Rule Numbers.
        :rtype: list.
        """
        network_acl = client.describe_network_acls(NetworkAclIds=[network_acl_id])
        network_acl_entries = network_acl["NetworkAcls"][0]
        rule_nos = []
        for entry in network_acl_entries["Entries"]:
            rule_nos.append(entry["RuleNumber"])
        return rule_nos

    def find_and_remove_port(
        self, network_acl_id, client, network_acl_entries, port_no, rule_nos
    ):
        """Find and remove port 22 and 3389 from Network Acl Entries
        :param network_acl_id: Network Acl Id.
        :param client: Instance of the AWS boto3 client.
        :param network_acl_entries: List of Network Acl Entries.
        :param port_no: Port No. to remove.
        :param rule_nos: List of Rule Numbers.
        :type rule_nos: list.
        :type port_no: int.
        :type network_acl_entries: list.
        :type network_acl_id: str.
        :type client: object.
        :returns: None.
        :rtype: None.
        """
        for entry in network_acl_entries["Entries"]:
            if (
                entry["Egress"] is False
                and entry["RuleAction"] == "allow"
                and entry["Protocol"] in ["6", "-1"]
                and entry["CidrBlock"] == "0.0.0.0/0"
            ):
                if "PortRange" not in entry or entry["PortRange"] == {
                    "From": port_no,
                    "To": port_no,
                }:
                    client.delete_network_acl_entry(
                        Egress=False,
                        NetworkAclId=network_acl_id,
                        RuleNumber=entry["RuleNumber"],
                    )
                elif (
                    entry["PortRange"]["From"] < port_no
                    and entry["PortRange"]["To"] == port_no
                ):
                    portrange_to = port_no - 1
                    if "CidrBlock" not in entry:
                        client.replace_network_acl_entry(
                            Egress=entry["Egress"],
                            Ipv6CidrBlock=entry["Ipv6CidrBlock"],
                            NetworkAclId=network_acl_id,
                            PortRange={
                                "From": entry["PortRange"]["From"],
                                "To": portrange_to,
                            },
                            Protocol=entry["Protocol"],
                            RuleAction=entry["RuleAction"],
                            RuleNumber=entry["RuleNumber"],
                        )
                    else:
                        client.replace_network_acl_entry(
                            CidrBlock=entry["CidrBlock"],
                            Egress=entry["Egress"],
                            NetworkAclId=network_acl_id,
                            PortRange={
                                "From": entry["PortRange"]["From"],
                                "To": portrange_to,
                            },
                            Protocol=entry["Protocol"],
                            RuleAction=entry["RuleAction"],
                            RuleNumber=entry["RuleNumber"],
                        )
                elif (
                    entry["PortRange"]["From"] < port_no
                    and entry["PortRange"]["To"] > port_no
                ):
                    rule_no = entry["RuleNumber"] + 10
                    while rule_no in rule_nos:
                        rule_no = rule_no + 10

                    if "CidrBlock" not in entry:
                        client.replace_network_acl_entry(
                            Egress=entry["Egress"],
                            Ipv6CidrBlock=entry["Ipv6CidrBlock"],
                            NetworkAclId=network_acl_id,
                            PortRange={
                                "From": entry["PortRange"]["From"],
                                "To": port_no - 1,
                            },
                            Protocol=entry["Protocol"],
                            RuleAction=entry["RuleAction"],
                            RuleNumber=entry["RuleNumber"],
                        )
                        portrange_from = port_no + 1

                        client.create_network_acl_entry(
                            Egress=entry["Egress"],
                            Ipv6CidrBlock=entry["Ipv6CidrBlock"],
                            NetworkAclId=network_acl_id,
                            PortRange={
                                "From": portrange_from,
                                "To": entry["PortRange"]["To"],
                            },
                            Protocol=entry["Protocol"],
                            RuleAction=entry["RuleAction"],
                            RuleNumber=rule_no,
                        )
                        rule_nos.append(rule_no)
                    else:
                        client.replace_network_acl_entry(
                            CidrBlock=entry["CidrBlock"],
                            Egress=entry["Egress"],
                            NetworkAclId=network_acl_id,
                            PortRange={
                                "From": entry["PortRange"]["From"],
                                "To": port_no - 1,
                            },
                            Protocol=entry["Protocol"],
                            RuleAction=entry["RuleAction"],
                            RuleNumber=entry["RuleNumber"],
                        )
                        portrange_from = port_no + 1

                        client.create_network_acl_entry(
                            CidrBlock=entry["CidrBlock"],
                            Egress=entry["Egress"],
                            NetworkAclId=network_acl_id,
                            PortRange={
                                "From": portrange_from,
                                "To": entry["PortRange"]["To"],
                            },
                            Protocol=entry["Protocol"],
                            RuleAction=entry["RuleAction"],
                            RuleNumber=rule_no,
                        )
                        rule_nos.append(rule_no)

    def remediate(self, region, client, network_acl_id, cloud_account_id):
        """Remove Network ACL Rules that allows public access to administration ports (3389 and 22)
        :param region: The buckets region
        :param client: Instance of the AWS boto3 client.
        :param network_acl_id: Network Acl Id.
        :param cloud_account_id: AWS Account Id.
        :type region: str.
        :type client: object.
        :param network_acl_id: str.
        :type cloud_account_id: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """
        try:
            logging.info("executing client.describe_network_acls to get network acl")
            port_nos = [22, 3389]
            for port_no in port_nos:
                rule_nos = self.create_list_of_rule_nos(network_acl_id, client)
                network_acl = client.describe_network_acls(
                    NetworkAclIds=[network_acl_id]
                )
                network_acl_entries = network_acl["NetworkAcls"][0]
                self.find_and_remove_port(
                    network_acl_id, client, network_acl_entries, port_no, rule_nos
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
        client = boto3.client("ec2", params["region"])
        logging.info("acquired ec2 client and parsed params - starting remediation")
        rc = self.remediate(client=client, **params)
        return rc


if __name__ == "__main__":
    logging.info("aws_cloudtrail_logs_encrypted.py called - running now")
    obj = RemoveAdministrationPortsPublicAccess()
    obj.run(sys.argv)
