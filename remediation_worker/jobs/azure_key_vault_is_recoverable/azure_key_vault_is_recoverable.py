import json
import os
import sys
import logging

from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.identity import ClientSecretCredential
from azure.mgmt.keyvault.models import VaultPatchParameters, VaultPatchProperties

logging.basicConfig(level=logging.INFO)


class KeyVaultIsRecoverable(object):
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
        logging.info(f"  key_vault_name: {object_id}")
        logging.info(f"  subscription_id: {subscription_id}")
        logging.info(f"  region: {region}")

        return {
            "resource_group_name": resource_group_name,
            "key_vault_name": object_id,
            "subscription_id": subscription_id,
            "region": region,
        }

    def remediate(self, client, resource_group_name, key_vault_name):
        """Enable Soft Delete and Purge Protection for Key Vault
        :param client: Instance of the Azure KeyVaultManagementClient.
        :param resource_group_name: The name of the resource group.
        :param key_vault_name: Name of the Key Vault.
        :type resource_group_name: str.
        :type key_vault_name: str.
        :type client: object.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: msrestazure.azure_exceptions.CloudError
        """

        logging.info("Enabling Soft Delete and Purge Protection for the Key Vault")

        try:
            key_vault = client.vaults.get(
                resource_group_name=resource_group_name, vault_name=key_vault_name,
            )

            if (
                key_vault.properties.enable_soft_delete is True
                and key_vault.properties.enable_purge_protection is None
            ):
                vault_properties = VaultPatchProperties(enable_purge_protection=True)

            elif key_vault.properties.enable_soft_delete is None:
                vault_properties = VaultPatchProperties(
                    enable_soft_delete=True,
                    soft_delete_retention_in_days=90,
                    enable_purge_protection=True,
                )

            logging.info("    executing client.vaults.update")
            logging.info(f"      resource_group_name={resource_group_name}")
            logging.info(f"      vault_name={key_vault_name}")
            client.vaults.update(
                resource_group_name=resource_group_name,
                vault_name=key_vault_name,
                parameters=VaultPatchParameters(properties=vault_properties),
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

        client = KeyVaultManagementClient(credential, params["subscription_id"])
        return self.remediate(
            client, params["resource_group_name"], params["key_vault_name"],
        )


if __name__ == "__main__":
    sys.exit(KeyVaultIsRecoverable().run(sys.argv))
