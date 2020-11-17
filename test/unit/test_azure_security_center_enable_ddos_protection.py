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
from mock import Mock
from remediation_worker.jobs.azure_security_center_enable_ddos_protection.azure_security_center_enable_ddos_protection import (
    VirtualNetworkEnableDdosProtection,
)


@pytest.fixture
def valid_payload():
    return """
{
    "notificationInfo": {
        "RuleId": "3abf3147-ea53-4302-b237-caab4d764c77",
        "Service": "Network",
        "FindingInfo": {
            "FindingId": "d0431afd-b82e-4021-8aa6-ba3cf5c60ef7",
            "ObjectId": "vnet_name",
            "ObjectChain": "{\\"cloudAccountId\\":\\"subscription_id\\",\\"entityId\\":\\"Azure.Network.d687b1a3-9b78-43b1-a17b-7de297fd1fce.resource_group_name.network.virtual_network_name\\",\\"entityName\\":\\"virtual_network_name\\",\\"entityType\\":\\"Azure.Network.virtualnetwork\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"d687b1a3-9b78-43b1-a17b-7de297fd1fce\\",\\"provider\\":\\"Azure\\",\\"region\\":\\"eastus\\",\\"service\\":\\"Network\\",\\"properties\\":[{\\"name\\":\\"ResourceGroup\\",\\"stringV\\":\\"resource_group_name\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestEnableDdosProtection(object):
    def test_parse_payload(self, valid_payload):
        params = VirtualNetworkEnableDdosProtection().parse(valid_payload)
        assert params["virtual_network_name"] == "vnet_name"
        assert params["resource_group_name"] == "resource_group_name"
        assert params["subscription_id"] == "subscription_id"
        assert params["region"] == "region"

    def test_remediate_success(self):
        client = Mock()
        action = VirtualNetworkEnableDdosProtection()
        DdosProtectionPlanListResult = Mock()
        ddos_plans_list = []
        ddos_plans_list.append(DdosProtectionPlanListResult)
        client.ddos_protection_plans.list.return_value = ddos_plans_list
        assert (
            action.remediate(
                client, "resource_group", "virtual_network_name", "subscription_id"
            )
            == 0
        )
        assert client.virtual_networks.begin_create_or_update.call_count == 1

        call_args = client.virtual_networks.begin_create_or_update.call_args
        updated_vnet = call_args[1]["parameters"]
        assert updated_vnet.enable_ddos_protection is True

    def test_remediate_failure(self):
        client = Mock()
        action = VirtualNetworkEnableDdosProtection()
        ddos_plans_list = []
        client.ddos_protection_plans.list.return_value = ddos_plans_list
        assert (
            action.remediate(
                client, "resource_group", "virtual_network_name", "subscription_id"
            )
            == 1
        )

    def test_remediate_with_exception(self):
        client = Mock()
        client.virtual_networks.begin_create_or_update.side_effect = Exception
        action = VirtualNetworkEnableDdosProtection()
        with pytest.raises(Exception):
            assert action.remediate(client, "security_group_id", "resource_group")
