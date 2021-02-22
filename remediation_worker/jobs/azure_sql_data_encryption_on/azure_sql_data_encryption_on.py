import json
import os
import sys
import logging

from azure.mgmt.sql import SqlManagementClient
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.sql.models import TransparentDataEncryptionStatus

logging.basicConfig(level=logging.INFO)


class EnableSqlDataEncryption(object):
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
        object_components = object_id.split(".")
        server_name = object_components[0]
        database_name = object_components[-1]

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
        logging.info(f"  sql_server_name: {server_name}")
        logging.info(f"  sql_database_name: {database_name}")
        logging.info(f"  subscription_id: {subscription_id}")
        logging.info(f"  region: {region}")
        return {
            "resource_group_name": resource_group_name,
            "sql_server_name": server_name,
            "subscription_id": subscription_id,
            "sql_database_name": database_name,
            "region": region,
        }

    def remediate(
        self, client, resource_group_name, sql_server_name, sql_database_name
    ):
        """Enable Transparent Data Encryption for SQL Dtabase
        :param client: Instance of the Azure SqlManagementClient.
        :param resource_group_name: The name of the resource group to which the SQL Server belongs.
        :param sql_server_name: The name of the SQL Server.
        :param sql_database_name: The name of the SQL Database.
        :type resource_group_name: str.
        :type sql_server_name: str.
        :type sql_database_name: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: msrestazure.azure_exceptions.CloudError
        """

        logging.info("Enabling Transparent Data Encryption for SQL Dtabase")

        try:
            logging.info(
                "    executing client.transparent_data_encryptions.create_or_update"
            )
            logging.info(f"      resource_group_name={resource_group_name}")
            logging.info(f"      server_name={sql_server_name}")
            logging.info(f"      database_name={sql_database_name}")

            client.transparent_data_encryptions.create_or_update(
                resource_group_name=resource_group_name,
                server_name=sql_server_name,
                database_name=sql_database_name,
                status=TransparentDataEncryptionStatus.enabled,
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

        credentials = ServicePrincipalCredentials(
            client_id=os.environ.get("AZURE_CLIENT_ID"),
            secret=os.environ.get("AZURE_CLIENT_SECRET"),
            tenant=os.environ.get("AZURE_TENANT_ID"),
        )

        client = SqlManagementClient(credentials, params["subscription_id"])
        return self.remediate(
            client,
            params["resource_group_name"],
            params["sql_server_name"],
            params["sql_database_name"],
        )


if __name__ == "__main__":
    sys.exit(EnableSqlDataEncryption().run(sys.argv))
