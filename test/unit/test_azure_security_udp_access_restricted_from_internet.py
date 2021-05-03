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
from remediation_worker.jobs.azure_security_udp_access_restricted_from_internet.azure_security_udp_access_restricted_from_internet import (
    RestrictUdpAccessFromInternet,
)
from azure.mgmt.network.models import NetworkSecurityGroup, SecurityRule


@pytest.fixture
def valid_payload():
    return """
{
    "notificationInfo": {
        "RuleId": "99d645b8-aa87-11ea-bb37-0242ac130002",
        "Service": "NetworkSecurityGroup",
        "FindingInfo": {
            "FindingId": "9b2da5e9-bb96-4298-b2c1-e6c341b44c5f",
            "ObjectId": "network_security_group_name",
            "ObjectChain": "{\\"cloudAccountId\\":\\"subscription_id\\",\\"entityId\\":\\"Azure.Network.d687b1a3-9b78-43b1-a17b-7de297fd1fce.resource_group_name.NetworkSecurityGroup.testingresourcename\\",\\"entityName\\":\\"testingresourcename\\",\\"entityType\\":\\"Azure.Network.NetworkSecurityGroup\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"d687b1a3-9b78-43b1-a17b-7de297fd1fce\\",\\"provider\\":\\"Azure\\",\\"region\\":\\"eastus\\",\\"service\\":\\"Storage\\", \\"properties\\":[{\\"name\\":\\"ResourceGroup\\",\\"stringV\\":\\"resource_group_name\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestRestrictUdpAccessFromInternet(object):
    def test_parse_payload(self, valid_payload):
        params = RestrictUdpAccessFromInternet().parse(valid_payload)
        assert params["network_security_group_name"] == "network_security_group_name"
        assert params["resource_group_name"] == "resource_group_name"
        assert params["subscription_id"] == "subscription_id"
        assert params["region"] == "region"

    def test_remediate_success(self):
        client = Mock()
        action = RestrictUdpAccessFromInternet()
        security_rule1 = SecurityRule(
            id="/subscriptions/d687b1a3-9b78-43b1-a17b-7de297fd1fce/resourceGroups/accelerators-team-resources/providers/Microsoft.Network/networkSecurityGroups/port_rules_testing_2/securityRules/Port_23",
            name="Port_23",
            protocol="TCP",
            source_port_range="*",
            destination_port_range="23",
            source_address_prefix="*",
            source_address_prefixes=[],
            access="Allow",
            priority=110,
            direction="Inbound",
        )
        security_rule2 = SecurityRule(
            id="/subscriptions/d687b1a3-9b78-43b1-a17b-7de297fd1fce/resourceGroups/accelerators-team-resources/providers/Microsoft.Network/networkSecurityGroups/port_rules_testing_2/securityRules/Port_23",
            name="Port_21",
            protocol="UDP",
            source_port_range="*",
            destination_port_range="21",
            source_address_prefix="*",
            source_address_prefixes=[],
            access="Allow",
            priority=100,
            direction="Inbound",
        )

        client.network_security_groups.get.return_value = NetworkSecurityGroup(
            id="/subscriptions/d687b1a3-9b78-43b1-a17b-7de297fd1fce/resourceGroups/accelerators-team-resources/providers/Microsoft.Network/networkSecurityGroups/port_rules_testing_2",
            location="eastus",
            security_rules=[security_rule1, security_rule2],
        )
        assert (
            action.remediate(client, "resource_group", "network_security_group_name")
            == 0
        )
        assert client.security_rules.begin_delete.call_count == 1
        assert client.network_security_groups.get.call_count == 1

    def test_remediate_with_exception(self):
        client = Mock()
        client.network_security_groups.get.return_value.side_effect = Exception
        action = RestrictUdpAccessFromInternet()
        with pytest.raises(Exception):
            assert action.remediate(client, "security_group_id", "resource_group")
