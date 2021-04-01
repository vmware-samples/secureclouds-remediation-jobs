import json
import os
import sys
import logging
import uuid
import datetime
from dateutil import parser as date_parse

from typing import List
from azure.core.paging import ItemPaged
from azure.keyvault.secrets import SecretClient
from azure.identity import ClientSecretCredential
from azure.graphrbac import GraphRbacManagementClient
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.keyvault.models import (
    AccessPolicyEntry,
    Permissions,
    SecretPermissions,
    AccessPolicyUpdateKind,
    VaultAccessPolicyParameters,
    VaultAccessPolicyProperties,
)
from azure.mgmt.authorization.models import (
    RoleAssignmentCreateParameters,
    RoleAssignmentListResult,
    RoleAssignmentProperties,
)

logging.basicConfig(level=logging.INFO)


class SetExpirationForSecret(object):
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
        object_components = object_id.split(".")
        key_vault_name = object_components[0]
        secret_name = object_components[-1]

        object_chain = remediation_entry["notificationInfo"]["FindingInfo"][
            "ObjectChain"
        ]
        object_chain_dict = json.loads(object_chain)
        subscription_id = object_chain_dict["cloudAccountId"]
        region = finding_info.get("Region")
        properties = object_chain_dict["properties"]

        logging.info(f"subscription_id: {subscription_id}")
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
        logging.info(f"  key_vault_name: {key_vault_name}")
        logging.info(f"  secret_name: {secret_name}")
        logging.info(f"  subscription_id: {subscription_id}")
        logging.info(f"  region: {region}")

        return {
            "resource_group_name": resource_group_name,
            "key_vault_name": key_vault_name,
            "secret_name": secret_name,
            "subscription_id": subscription_id,
            "region": region,
        }

    def ensure_secret_permissions(
        self,
        keyvault_client,
        client_authorization,
        key_vault_name,
        resource_group_name,
        scope,
        app_object_id,
        role_definition_id,
        subscription_id,
        guid,
        tenant_id,
    ):
        """Ensures that appropriate secret permissions are given to the app to update it.
        :param keyvault_client: Instance of the Azure KeyVaultManagementClient
        :param key_vault_name: Key Vault Name
        :param resource_group_name: Resource group name
        :param client_authorization: Instance of the Azure AuthorizationManagementClient.
        :param scope: Scope for which to check the existence of the Role Assignment.
        :param app_object_id: Object Id of the Application.
        :param role_definition_id: Role Definition Id.
        :param subscription_id: Azure Subscription Id.
        :param guid: UUID for role name.
        :param tenant_id: Azure tenant Id
        :type client_authorization: object
        :type scope: str
        :type app_object_id: str
        :type role_definition_id: str
        :type keyvault_client: object
        :type key_vault_name: str
        :type resource_group_name: str
        :type subscription_id: str
        :type guid: str
        :type tenant_id: str
        """
        if self.check_rbac_enabled(
            keyvault_client, key_vault_name, resource_group_name
        ):
            if self.check_role_assignment(
                client_authorization, scope, app_object_id, role_definition_id
            ):
                return
            else:
                self.create_role_assignment(
                    subscription_id,
                    client_authorization,
                    guid,
                    scope,
                    app_object_id,
                    key_vault_name,
                )
        else:
            # Update Key Vault Access policy to provide access for the application to update Secret
            self.update_key_vault_access_policy(
                keyvault_client,
                resource_group_name,
                key_vault_name,
                tenant_id,
                app_object_id,
            )

    def check_rbac_enabled(self, keyvault_client, key_vault_name, resource_group_name):
        """Checks if RBAC is enabled for Key Vault
        :param keyvault_client: Instance of the Azure KeyVaultManagementClient
        :param key_vault_name: Key Vault Name
        :param resource_group_name: Resource group name
        :type keyvault_client: object
        :type key_vault_name: str
        :type resource_group_name: str
        :returns: Boolean indicating RBAC is enabled or disabled
        :rtype: bool
        """
        key_vault = keyvault_client.vaults.get(
            resource_group_name=resource_group_name, vault_name=key_vault_name,
        )
        return key_vault.properties.enable_rbac_authorization

    def check_role_assignment(
        self, client_authorization, scope, app_object_id, role_definition_id
    ):
        """Checks if the Role Assignment already exists
        :param client_authorization: Instance of the Azure AuthorizationManagementClient.
        :param scope: Scope for which to check the existence of the Role Assignment.
        :param app_object_id: Object Id of the Application.
        :param role_definition_id: Role Definition Id.
        :type client_authorization: object
        :type scope: str
        :type app_object_id: str
        :type role_definition_id: str
        :returns: Boolean indicating success or failure
        :rtype: bool
        """
        role_assignment_paged: ItemPaged[
            RoleAssignmentListResult
        ] = client_authorization.role_assignments.list_for_scope(scope=scope)
        role_assignment_list: List[dict] = list(role_assignment_paged)
        for role in role_assignment_list:
            if (
                role.principal_id == app_object_id
                and role.role_definition_id == role_definition_id
            ):
                return True
        return False

    def create_role_assignment(
        self,
        subscription_id,
        client_authorization,
        guid,
        scope,
        app_object_id,
        key_vault_name,
    ):
        """Creates a Role Assignment
        :param subscription_id: Azure Subscription Id
        :param client_authorization: Instance of the Azure AuthorizationManagementClient.
        :param guid: UUID for role name
        :param scope: The scope of the role assignment.
        :param app_object_id: Object Id of the Application
        :param key_vault_name: Key Vault Name
        :type client_authorization: object
        :type subscription_id: str
        :type guid: str
        :type scope: str
        :type principalId: str
        :type key_vault_name: str
        :returns: None
        :rtype: None
        """
        logging.info(
            f"Creating a Role Assignment for Key Vault {key_vault_name} and assigning Key Vault Secrets Officer Role to the application"
        )
        logging.info("executing client_authorization.role_assignments.create")
        logging.info(f"      scope={scope}")
        logging.info(f"      role_assignment_name={guid}")
        client_authorization.role_assignments.create(
            scope=scope,
            role_assignment_name=guid,
            parameters=RoleAssignmentCreateParameters(
                properties=RoleAssignmentProperties(
                    role_definition_id=f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/b86a8fe4-44ce-4948-aee5-eccb2c155cd7",
                    principal_id=app_object_id,
                ),
            ),
        )

    def update_key_vault_access_policy(
        self,
        keyvault_client,
        resource_group_name,
        key_vault_name,
        tenant_id,
        app_object_id,
    ):
        """Updates Key Vault Access Policy
        :param keyvault_client: Instance of the Azure KeyVaultManagementClient.
        :param resource_group_name: The name of the resource group.
        :param key_vault_name: Name of the Key Vault.
        :param region: The location in which the Key Vault exists.
        :param tenant_id: Azure tenant Id
        :param app_object_id: Object Id of the application
        :param stg_principal_id: Principal Id of the Storage Account
        :type keyvault_client: object
        :type resource_group_name: str
        :type key_vault_name: str
        :type region: str
        :type tenant_id: str
        :type app_object_id: str
        :type stg_principal_id: str
        :returns: None
        :rtype: None
        """
        access_policy_app = AccessPolicyEntry(
            tenant_id=tenant_id,
            object_id=app_object_id,
            permissions=Permissions(
                secrets=[
                    SecretPermissions.GET,
                    SecretPermissions.LIST,
                    SecretPermissions.SET,
                ],
            ),
        )
        access_policy = [access_policy_app]

        logging.info("Updating Key Vault Access Policy")
        logging.info("executing keyvault_client.vaults.update_access_policy")
        logging.info(f"      resource_group_name={resource_group_name}")
        logging.info(f"      vault_name={key_vault_name}")
        keyvault_client.vaults.update_access_policy(
            resource_group_name=resource_group_name,
            vault_name=key_vault_name,
            operation_kind=AccessPolicyUpdateKind.ADD,
            parameters=VaultAccessPolicyParameters(
                properties=VaultAccessPolicyProperties(access_policies=access_policy),
            ),
        )

    def remediate(
        self,
        tenant_id,
        client_id,
        secret_client,
        keyvault_client,
        graph_client,
        client_authorization,
        resource_group_name,
        key_vault_name,
        secret_name,
        subscription_id,
    ):
        """Set Expiry date for Secret
        :param client_id: Azure Client ID.
        :param tenant_id: Azure Tenant ID.
        :param graph_client: Instance of the AzureGraphRbacManagementClient.
        :param keyvault_client: Instance of the Azure KeyVaultManagementClient.
        :param resource_group_name: The name of the resource group to which the storage account belongs.
        :param key_vault_name: The name of the key vault.
        :param secret_name: Name of the secret.
        :param subscription_id: Azure Subscription Id
        :type client_id: str
        :type tenant_id: str
        :type graph_client: object
        :type keyvault_client: object
        :type resource_group_name: str
        :type key_vault_name: str
        :type secret_name:str
        :type subscription_id: str
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: msrestazure.azure_exceptions.CloudError
        """
        try:
            tenant_id = os.environ.get("AZURE_TENANT_ID")
            guid = uuid.uuid4()

            # Get application object Id
            logging.info(
                "executing graph_client.applications.get_service_principals_id_by_app_id"
            )
            app_details = graph_client.applications.get_service_principals_id_by_app_id(
                application_id=client_id
            )

            scope = f"/subscriptions/{subscription_id}/resourcegroups/{resource_group_name}/providers/Microsoft.KeyVault/vaults/{key_vault_name}"
            role_definition_id = f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/b86a8fe4-44ce-4948-aee5-eccb2c155cd7"

            # Check if the required permissions to update the secret is given to the application, if not then give the required permissions.
            self.ensure_secret_permissions(
                keyvault_client,
                client_authorization,
                key_vault_name,
                resource_group_name,
                scope,
                app_details.value,
                role_definition_id,
                subscription_id,
                guid,
                tenant_id,
            )

            logging.info("Setting Expiry date for Secret")
            d = (
                datetime.datetime.utcnow()
                .replace(tzinfo=datetime.timezone.utc)
                .isoformat()
            )
            date = datetime.datetime.strptime(
                d[0:19], "%Y-%m-%dT%H:%M:%S"
            ) + datetime.timedelta(days=730)
            expires_on = date_parse.parse(
                date.replace(microsecond=0, tzinfo=datetime.timezone.utc).isoformat()
            )

            # Setting Expiry date for Secret
            logging.info("executing secret_client.update_secret_properties")
            secret_client.update_secret_properties(
                name=secret_name, expires_on=expires_on,
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

        client_id = os.environ.get("AZURE_CLIENT_ID")
        client_secret = os.environ.get("AZURE_CLIENT_SECRET")
        tenant_id = os.environ.get("AZURE_TENANT_ID")
        key_vault_name = params["key_vault_name"]

        # credential for Key Vault management client
        credential = ClientSecretCredential(
            client_id=client_id, client_secret=client_secret, tenant_id=tenant_id,
        )

        # credential for AzureGraphRbacManagementClient
        credentials = ServicePrincipalCredentials(
            client_id=client_id,
            secret=client_secret,
            tenant=tenant_id,
            resource="https://graph.windows.net",
        )

        keyvault_client = KeyVaultManagementClient(
            credential, params["subscription_id"]
        )

        graph_client = GraphRbacManagementClient(credentials, tenant_id, base_url=None)

        secret_client = SecretClient(
            vault_url=f"https://{key_vault_name}.vault.azure.net/",
            credential=credential,
        )

        client_authorization = AuthorizationManagementClient(
            credential, params["subscription_id"], api_version="2018-01-01-preview"
        )

        return self.remediate(
            tenant_id,
            client_id,
            secret_client,
            keyvault_client,
            graph_client,
            client_authorization,
            params["resource_group_name"],
            params["key_vault_name"],
            params["secret_name"],
            params["subscription_id"],
        )


if __name__ == "__main__":
    sys.exit(SetExpirationForSecret().run(sys.argv))
