import json
import os
import sys
import logging
import random
import string
import uuid

from azure.identity import ClientSecretCredential
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.sql.models import (
    ServerBlobAuditingPolicy,
    BlobAuditingPolicyState,
    ResourceIdentity,
    IdentityType,
    Server,
)
from azure.mgmt.storage.models import (
    StorageAccountCreateParameters,
    NetworkRuleSet,
    Sku,
    SkuName,
    SkuTier,
    DefaultAction,
)
from azure.mgmt.authorization.models import (
    RoleAssignmentCreateParameters,
    PrincipalType,
)

logging.basicConfig(level=logging.INFO)


def generate_storage_account_name(prefix):
    prefix = "".join(i for i in prefix if i.islower() or i.isdigit())
    if len(prefix) >= 15:
        prefix = str(prefix[:14])
    result_str = prefix + "auditlogs"
    return result_str


def create_storage_account(
    resource_group_name, name, region, client_storage,
):
    create_params = StorageAccountCreateParameters(
        location=region,
        sku=Sku(name=SkuName.STANDARD_LRS, tier=SkuTier.STANDARD),
        kind="StorageV2",
        enable_https_traffic_only=True,
        network_rule_set=NetworkRuleSet(default_action=DefaultAction.DENY),
    )
    poller = client_storage.storage_accounts.begin_create(
        resource_group_name=resource_group_name,
        account_name=name,
        parameters=create_params,
    )
    return poller.result()


def create_role_assignment(
    stg_account_name, subscription_id, client_authorization, guid, Scope, principalId,
):
    client_authorization.role_assignments.create(
        scope=Scope,
        role_assignment_name=guid,
        parameters=RoleAssignmentCreateParameters(
            role_definition_id=f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/ba92f5b4-2d11-453d-a403-e96b0029c9fe",
            principal_id=principalId,
            principal_type=PrincipalType.service_principal,
        ),
    )


class SqlServerEnableBlobAuditingPolicy(object):
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
        logging.info(f"  sql_server_name: {object_id}")
        logging.info(f"  subscription_id: {subscription_id}")
        logging.info(f"  region: {region}")
        return {
            "resource_group_name": resource_group_name,
            "sql_server_name": object_id,
            "subscription_id": subscription_id,
            "region": region,
        }

    def remediate(
        self,
        client,
        client_storage,
        client_authorization,
        resource_group_name,
        sql_server_name,
        region,
        subscription_id,
    ):
        """Enable Server blob auditing policy for Azure SQL Server
        :param client: Instance of the Azure SqlManagementClient.
        :param client_storage: Instance of the Azure StorageManagementClient.
        :param resource_group_name: The name of the resource group to which the SQL Server belongs.
        :param sql_server_name: The name of the SQL Server.
        :type resource_group_name: str.
        :type sql_server_name: str.
        :type region: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: msrestazure.azure_exceptions.CloudError
        """

        try:
            server = client.servers.get(
                resource_group_name=resource_group_name, server_name=sql_server_name,
            )
            if server.identity is None:
                logging.info(
                    f"Assigning Azure Active Directory Identity to the SQL Database Server {sql_server_name}"
                )
                logging.info("executing client.servers.update")
                logging.info(f"      resource_group_name={resource_group_name}")
                logging.info(f"      server_name={sql_server_name}")
                updated_server = client.servers.update(
                    resource_group_name=resource_group_name,
                    server_name=sql_server_name,
                    parameters=Server(
                        location=region,
                        identity=ResourceIdentity(type=IdentityType.system_assigned),
                    ),
                ).result()
                principalId = updated_server.identity.principal_id
            else:
                principalId = server.identity.principal_id

            stg_account_name = generate_storage_account_name(sql_server_name)
            logging.info(f"Creating a storage account with name {stg_account_name}")
            logging.info("executing client_storage.storage_accounts.begin_create")
            logging.info(f"      resource_group_name={resource_group_name}")
            logging.info(f"      storage_account_name={stg_account_name}")

            create_storage_account(
                resource_group_name, stg_account_name, region, client_storage
            )

            guid = uuid.uuid4()
            Scope = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.Storage/storageAccounts/{stg_account_name}"

            logging.info(
                f"Creating a Role Assignment for Storage Account {stg_account_name} and assigning Storage Blob Data Contributer Role to the SQL Database Server {sql_server_name}"
            )
            logging.info("executing client_authorization.role_assignments.create")
            logging.info(f"      scope={Scope}")
            logging.info(f"      role_assignment_name={guid}")

            create_role_assignment(
                stg_account_name,
                subscription_id,
                client_authorization,
                guid,
                Scope,
                principalId,
            )

            logging.info("Enabling Server blob auditing policy for Azure SQL Server")
            logging.info(
                "    executing client.server_blob_auditing_policies.create_or_update"
            )
            logging.info(f"      resource_group_name={resource_group_name}")
            logging.info(f"      server_name={sql_server_name}")

            client.server_blob_auditing_policies.create_or_update(
                resource_group_name=resource_group_name,
                server_name=sql_server_name,
                parameters=ServerBlobAuditingPolicy(
                    state=BlobAuditingPolicyState.enabled,
                    storage_endpoint=f"https://{stg_account_name}.blob.core.windows.net/",
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
        credentials_stg = ClientSecretCredential(
            client_id=os.environ.get("AZURE_CLIENT_ID"),
            client_secret=os.environ.get("AZURE_CLIENT_SECRET"),
            tenant_id=os.environ.get("AZURE_TENANT_ID"),
        )

        client = SqlManagementClient(
            credentials, params["subscription_id"], base_url=None
        )
        client_storage = StorageManagementClient(
            credentials_stg, params["subscription_id"]
        )
        client_authorization = AuthorizationManagementClient(
            credentials, params["subscription_id"]
        )
        return self.remediate(
            client,
            client_storage,
            client_authorization,
            params["resource_group_name"],
            params["sql_server_name"],
            params["region"],
            params["subscription_id"],
        )


if __name__ == "__main__":
    sys.exit(SqlServerEnableBlobAuditingPolicy().run(sys.argv))
