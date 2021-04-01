import json
import os
import sys
import logging

from azure.mgmt.sql import SqlManagementClient
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.sql.models import ServerSecurityAlertPolicy, SecurityAlertPolicyState

logging.basicConfig(level=logging.INFO)


class SetAdvanceThreatProtectionToAll(object):
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

        region = finding_info.get("Region")

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
        logging.info(f"  sql_server_name: {object_id}")
        logging.info(f"  subscription_id: {subscription_id}")
        logging.info(f"  region: {region}")
        return {
            "resource_group_name": resource_group_name,
            "sql_server_name": object_id,
            "subscription_id": subscription_id,
            "region": region,
        }

    def remediate(self, client, resource_group_name, sql_server_name):
        """Set Advanced Threat Protection types to all
        :param client: Instance of the Azure SqlManagementClient.
        :param resource_group_name: The name of the resource group to which the SQL Server belongs.
        :param sql_server_name: The name of the SQL Server.
        :type resource_group_name: str.
        :type sql_server_name: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: msrestazure.azure_exceptions.CloudError
        """

        logging.info("Setting Advanced Threat Protection types to all")
        try:
            logging.info(
                "    executing client.server_security_alert_policies.create_or_update"
            )
            logging.info(f"      resource_group_name={resource_group_name}")
            logging.info(f"      server_name={sql_server_name}")

            client.server_security_alert_policies.create_or_update(
                resource_group_name=resource_group_name,
                server_name=sql_server_name,
                parameters=ServerSecurityAlertPolicy(
                    state=SecurityAlertPolicyState.enabled, disabled_alerts=[]
                ),
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
        client = SqlManagementClient(
            credentials, params["subscription_id"], base_url=None
        )

        return self.remediate(
            client, params["resource_group_name"], params["sql_server_name"],
        )


if __name__ == "__main__":
    sys.exit(SetAdvanceThreatProtectionToAll().run(sys.argv))
