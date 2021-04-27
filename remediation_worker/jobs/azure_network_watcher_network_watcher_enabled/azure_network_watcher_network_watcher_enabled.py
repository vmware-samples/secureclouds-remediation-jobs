import json
import os
import sys
import logging

from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource.subscriptions import SubscriptionClient
from azure.mgmt.network.models import NetworkWatcherListResult, NetworkWatcher
from azure.mgmt.resource.subscriptions.models import LocationListResult
from azure.identity import ClientSecretCredential
from azure.core.exceptions import HttpResponseError
from azure.core.paging import ItemPaged
from typing import List

logging.basicConfig(level=logging.INFO)


class EnableNetworkWatcher(object):
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

        logging.info(f"cloud_account_id: {subscription_id}")

        if object_id is None:
            raise Exception(
                "Missing parameters for 'payload.notificationInfo.ObjectId'."
            )

        logging.info("parsed params")
        logging.info(f"  subscription_id: {object_id}")

        return {
            "subscription_id": object_id,
        }

    def remediate(self, client, subscription_client, subscription_id):
        """Enable Network Watcher for all the regions
        :param client: Instance of the Azure MySQLManagementClient.
        :param resource_group_name: The name of the resource group.
        :param subscription_id: Azure Subscription Id.
        :type resource_group_name: str.
        :type subscription_id: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: msrestazure.azure_exceptions.CloudError
        """

        logging.info("Enabling Network Watcher for all the regions")

        try:
            network_watcher_paged: ItemPaged[
                NetworkWatcherListResult
            ] = client.network_watchers.list_all()
            network_watcher_list: List[dict] = list(network_watcher_paged)
            number_of_network_watcher: int = len(network_watcher_list)
            network_watcher_enabled_regions = []
            if number_of_network_watcher > 0:
                for network_watcher in network_watcher_list:
                    network_watcher_enabled_regions.append(network_watcher.location)

            location_list_paged: ItemPaged[
                LocationListResult
            ] = subscription_client.subscriptions.list_locations(
                subscription_id=subscription_id
            )
            loction_list: List[dict] = list(location_list_paged)
            for location in loction_list:
                if location.name in network_watcher_enabled_regions:
                    continue
                else:
                    try:
                        client.network_watchers.create_or_update(
                            resource_group_name="NetworkWatcherRG",
                            network_watcher_name="NetworkWatcher_" + location.name,
                            parameters=NetworkWatcher(location=location.name,),
                        )
                    except HttpResponseError as e:
                        if e.status_code == 400:
                            print(location.name)
                            continue
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
        subscription_client = SubscriptionClient(credential)
        return self.remediate(client, subscription_client, params["subscription_id"],)


if __name__ == "__main__":
    sys.exit(EnableNetworkWatcher().run(sys.argv))
