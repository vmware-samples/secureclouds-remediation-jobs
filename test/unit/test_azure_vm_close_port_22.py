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

import pytest
from azure.mgmt.network.models import NetworkSecurityGroup, NetworkInterface
from azure.mgmt.network.models import SecurityRule
from azure.mgmt.compute.models import (
    VirtualMachine,
    NetworkProfile,
    NetworkInterfaceReference,
)
from mock import Mock

from remediation_worker.jobs.azure_vm_close_port_22.azure_vm_close_port_22 import (
    VMSecurityGroupClosePort22,
)


@pytest.fixture
def valid_payload1():
    return """
{
    "notificationInfo": {
        "RuleId": "5c6cc5e203dcc90f363146ce",
        "Service": "Network",
        "FindingInfo": {
            "FindingId": "e1606076-d55c-42c5-9ca7-93e933b1e672",
            "ObjectId": "vm_name",
            "ObjectChain": "{\\"cloudAccountId\\":\\"subscription_id\\",\\"entityId\\":\\"Azure.Storage.d687b1a3-9b78-43b1-a17b-7de297fd1fce.khanz-test.StorageAccount.testingresourcename\\",\\"entityName\\":\\"testingresourcename\\",\\"entityType\\":\\"Azure.Storage.StorageAccount\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"d687b1a3-9b78-43b1-a17b-7de297fd1fce\\",\\"provider\\":\\"Azure\\",\\"region\\":\\"eastus\\",\\"service\\":\\"Storage\\", \\"properties\\":[{\\"name\\":\\"ResourceGroup\\",\\"stringV\\":\\"resource_group_name\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestStorageAccountAllowHttpsTrafficOnly(object):
    def test_parse_payload(self, valid_payload1):
        params = VMSecurityGroupClosePort22().parse(valid_payload1)
        assert params["vm_name"] == "vm_name"
        assert params["resource_group_name"] == "resource_group_name"
        assert params["subscription_id"] == "subscription_id"
        assert params["region"] == "region"

    def test_remediate_success(self):
        compute_client = Mock()
        nw_profile = NetworkProfile(
            network_interfaces=[
                NetworkInterfaceReference(
                    id="/subscriptions/subscription_id/resourceGroups/resource_group/providers/Microsoft.Network"
                    "/networkInterfaces/vm_nameVMNic "
                )
            ]
        )

        compute_client.virtual_machines.get.return_value = VirtualMachine(
            id="/subscriptions/subscription_id/resourceGroups/resource_group/providers/Microsoft.Compute"
            "/virtualMachines/vm_name",
            location="eastus",
            network_profile=nw_profile,
        )
        nw_client = Mock()
        nw_client.network_interfaces.get.return_value = NetworkInterface(
            id="/subscriptions/subscription_id/resourceGroups/resource_group/providers/Microsoft.Network"
            "/networkInterfaces/vm_nameVMNic",
            network_security_group=NetworkSecurityGroup(
                id="/subscriptions/subscription_id/resourceGroups/resource_name/providers/Microsoft.Network"
                "/networkSecurityGroups/vm_nameNSG "
            ),
        )

        nw_client.network_security_groups.get.return_value = NetworkSecurityGroup(
            id="/subscriptions/subscription_id/resourceGroups/resource_name/providers/Microsoft.Network"
            "/networkSecurityGroups/vm_nameNSG",
            security_rules=[
                SecurityRule(
                    protocol="All",
                    access="Allow",
                    direction="Inbound",
                    source_address_prefix="*",
                    destination_port_ranges=["22", "3389"],
                ),
                SecurityRule(
                    protocol="All",
                    access="Allow",
                    direction="Inbound",
                    source_address_prefix="*",
                    destination_port_ranges=["20-30", "3389"],
                ),
                SecurityRule(
                    protocol="All",
                    access="Allow",
                    direction="Inbound",
                    source_address_prefix="*",
                    destination_port_range="22",
                ),
            ],
        )

        action = VMSecurityGroupClosePort22()
        assert (
            action.remediate(compute_client, nw_client, "resource_name", "vm_name") == 0
        )
        assert nw_client.network_security_groups.create_or_update.call_count == 1
        call_args = nw_client.network_security_groups.create_or_update.call_args
        updated_sg = call_args.args[2]
        security_rules = updated_sg.security_rules
        assert len(security_rules) == 2
        assert security_rules[0].destination_port_ranges == ["3389"]
        assert security_rules[1].destination_port_ranges == ["20-21", "23-30", "3389"]

    #
    def test_remediate_with_exception(self):
        client = Mock()
        client.network_security_groups.create_or_update.side_effect = Exception
        action = VMSecurityGroupClosePort22()
        with pytest.raises(Exception):
            assert action.remediate(client, "security_group_id", "resource_group")
