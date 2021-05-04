import json
import os
import sys
import logging

from azure.mgmt.rdbms.postgresql import PostgreSQLManagementClient
from azure.identity import ClientSecretCredential

logging.basicConfig(level=logging.INFO)


class DisableAzureServicesAccess(object):
    def parse(self, payload):
        """Parse payload received from Remediation Service.
        :param payload: JSON string containing parameters received from the remediation service.
        :type payload: str.
        :returns: Dictionary of parsed parameters
        :rtype: dict
        :raises: KeyError, JSONDecodeError
        """
        remediation_entry = json.loads(payload)

        object_id = remediation_entry["notificationInfo"]["FindingInfo"]["ObjectId"]

        region = remediation_entry["notificationInfo"]["FindingInfo"]["Region"]

        object_chain = remediation_entry["notificationInfo"]["FindingInfo"][
            "ObjectChain"
        ]
        object_chain_dict = json.loads(object_chain)
        subscription_id = object_chain_dict["cloudAccountId"]

        properties = object_chain_dict["properties"]
        resource_group_name = ""
        for property in properties:
            if property["name"] == "ResourceGroup" and property["type"] == "string":
                resource_group_name = property["stringV"]
                break

        logging.info("parsed params")
        logging.info(f"  resource_group_name: {resource_group_name}")
        logging.info(f"  account_name: {object_id}")
        logging.info(f"  subscription_id: {subscription_id}")
        logging.info(f"  region: {region}")

        return {
            "resource_group_name": resource_group_name,
            "postgre_server_name": object_id,
            "subscription_id": subscription_id,
            "region": region,
        }

    def remediate(self, client, resource_group_name, postgre_server_name):
        """Disable Allow Azure Services Access for PostgreSQL Server
        :param client: Instance of the Azure PostgreSQLManagementClient.
        :param resource_group_name: The name of the resource group.
        :param postgre_server_name: The name of the PostgreSQL Server.
        :type resource_group_name: str.
        :type postgre_server_name: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: msrestazure.azure_exceptions.CloudError
        """

        logging.info("Disable Allow Azure Services Access for PostgreSQL Server")

        try:
            logging.info("    executing client.firewall_rules.begin_delete")
            logging.info(f"      resource_group_name={resource_group_name}")
            logging.info(f"      server_name={postgre_server_name}")
            logging.info(f"      firewall_rule_name=AllowAllWindowsAzureIps")

            client.firewall_rules.begin_delete(
                resource_group_name=resource_group_name,
                server_name=postgre_server_name,
                firewall_rule_name="AllowAllWindowsAzureIps",
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

        client = PostgreSQLManagementClient(credential, params["subscription_id"])
        return self.remediate(
            client, params["resource_group_name"], params["postgre_server_name"],
        )


if __name__ == "__main__":
    sys.exit(DisableAzureServicesAccess().run(sys.argv))
