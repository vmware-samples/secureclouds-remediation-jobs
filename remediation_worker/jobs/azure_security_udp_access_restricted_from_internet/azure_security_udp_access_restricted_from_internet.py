import json
import os
import sys
import logging

from azure.mgmt.network import NetworkManagementClient
from azure.identity import ClientSecretCredential

logging.basicConfig(level=logging.INFO)

source_address_list = ["*", "Internet", "0.0.0.0/0", "0.0.0.0", "/0", "::/0"]


class RestrictUdpAccessFromInternet(object):
    def parse(self, payload):
        """Parse payload received from Remediation Service.
        :param payload: JSON string containing parameters received from the remediation service.
        :type payload: str.
        :returns: Dictionary of parsed parameters
        :rtype: dict
        :raises: KeyError, JSONDecodeError
        """
        remediation_entry = json.loads(payload)
        notification_info = remediation_entry.get("notificationInfo", None)
        finding_info = notification_info.get("FindingInfo", None)
        object_id = finding_info.get("ObjectId", None)

        object_chain = remediation_entry["notificationInfo"]["FindingInfo"][
            "ObjectChain"
        ]
        object_chain_dict = json.loads(object_chain)
        subscription_id = object_chain_dict["cloudAccountId"]
        region = finding_info.get("Region")
        properties = object_chain_dict["properties"]

        logging.info(f"cloud_account_id: {subscription_id}")
        logging.info(f"region: {region}")

        if object_id is None:
            raise Exception(
                "Missing parameters for 'payload.notificationInfo.ObjectId'."
            )
        resource_group_name = ""
        for property in properties:
            if property["name"] == "ResourceGroup" and property["type"] == "string":
                resource_group_name = property["stringV"]
                break

        logging.info("parsed params")
        logging.info(f"  resource_group_name: {resource_group_name}")
        logging.info(f"  network_security_group_name: {object_id}")
        logging.info(f"  subscription_id: {subscription_id}")
        logging.info(f"  region: {region}")

        return {
            "resource_group_name": resource_group_name,
            "network_security_group_name": object_id,
            "subscription_id": subscription_id,
            "region": region,
        }

    def remediate(self, client, resource_group_name, network_security_group_name):
        """Delete inbound security rule that allows open traffic on UDP port
        :param client: Instance of the Azure KeyVaultManagementClient.
        :param resource_group_name: The name of the resource group.
        :param key_vault_name: Name of the Key Vault.
        :type resource_group_name: str.
        :type key_vault_name: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: msrestazure.azure_exceptions.CloudError
        """

        logging.info(
            "Deleting inbound security rule that allows open traffic on UDP port"
        )

        try:
            network_security_group = client.network_security_groups.get(
                resource_group_name=resource_group_name,
                network_security_group_name=network_security_group_name,
            )
            security_rules = network_security_group.security_rules

            for rule in security_rules:
                if (
                    rule.protocol in ["*", "UDP"]
                    and rule.direction == "Inbound"
                    and rule.access == "Allow"
                    and (
                        rule.source_address_prefix in source_address_list
                        or any(
                            item in rule.source_address_prefixes
                            for item in source_address_list
                        )
                    )
                ):
                    # Delete all the rules that allows unrestricted access to UDP
                    logging.info("    executing client.security_rules.begin_delete")
                    logging.info(f"      resource_group_name={resource_group_name}")
                    logging.info(
                        f"      network_security_group_name={network_security_group_name}"
                    )
                    logging.info(f"      security_rule_name={rule.name}")
                    client.security_rules.begin_delete(
                        resource_group_name=resource_group_name,
                        network_security_group_name=network_security_group_name,
                        security_rule_name=rule.name,
                    )
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

        credential = ClientSecretCredential(
            client_id=os.environ.get("AZURE_CLIENT_ID"),
            client_secret=os.environ.get("AZURE_CLIENT_SECRET"),
            tenant_id=os.environ.get("AZURE_TENANT_ID"),
        )

        client = NetworkManagementClient(credential, params["subscription_id"])
        return self.remediate(
            client,
            params["resource_group_name"],
            params["network_security_group_name"],
        )


if __name__ == "__main__":
    sys.exit(RestrictUdpAccessFromInternet().run(sys.argv))
