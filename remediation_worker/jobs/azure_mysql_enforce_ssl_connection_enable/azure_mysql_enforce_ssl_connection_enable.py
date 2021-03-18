import json
import os
import sys
import logging

from azure.mgmt.rdbms.mysql import MySQLManagementClient
from azure.identity import ClientSecretCredential
from azure.mgmt.rdbms.mysql.models import ServerUpdateParameters

logging.basicConfig(level=logging.INFO)


class EnableSslEnforcement(object):
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
        logging.info(f"  mysql_server_name: {object_id}")
        logging.info(f"  subscription_id: {subscription_id}")
        logging.info(f"  region: {region}")

        return {
            "resource_group_name": resource_group_name,
            "mysql_server_name": object_id,
            "subscription_id": subscription_id,
            "region": region,
        }

    def remediate(self, client, resource_group_name, mysql_server_name):
        """Enable Enforce SSL connection for MySQL Server
        :param client: Instance of the Azure MySQLManagementClient.
        :param resource_group_name: The name of the resource group.
        :param mysql_server_name: The name of the MySQL Server.
        :type resource_group_name: str.
        :type mysql_server_name: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: msrestazure.azure_exceptions.CloudError
        """

        logging.info("Enabling Enforce SSL connection for MySQL Server")

        try:
            logging.info("    executing client.servers.begin_update")
            logging.info(f"      resource_group_name={resource_group_name}")
            logging.info(f"      server_name={mysql_server_name}")

            client.servers.begin_update(
                resource_group_name=resource_group_name,
                server_name=mysql_server_name,
                parameters=ServerUpdateParameters(ssl_enforcement="Enabled"),
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

        client = MySQLManagementClient(credential, params["subscription_id"])
        return self.remediate(
            client, params["resource_group_name"], params["mysql_server_name"],
        )


if __name__ == "__main__":
    sys.exit(EnableSslEnforcement().run(sys.argv))
