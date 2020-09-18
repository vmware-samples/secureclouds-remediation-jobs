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
from azure.mgmt.network.models import NetworkSecurityGroup
from azure.mgmt.network.models import SecurityRule
from mock import Mock

from remediation_worker.jobs.azure_network_security_group_close_port_22.azure_network_security_group_close_port_22 import (
    NetworkSecurityGroupClosePort22,
)


@pytest.fixture
def valid_payload1():
    return """
{
    "notificationInfo": {
        "RuleId": "5c6cc5d903dcc90f363146b6",
        "Service": "Network",
        "FindingInfo": {
            "FindingId": "e1606076-d55c-42c5-9ca7-93e933b1e672",
            "ObjectId": "security_group_name",
            "ObjectChain": "{\\"cloudAccountId\\":\\"subscription_id\\", \\"properties\\":[{\\"name\\":\\"ResourceGroup\\",\\"stringV\\":\\"resource_group_name\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestNetworkSecurityGroupClosePort22(object):
    def test_parse_payload(self, valid_payload1):
        params = NetworkSecurityGroupClosePort22().parse(valid_payload1)
        assert params["security_group_name"] == "security_group_name"
        assert params["resource_group_name"] == "resource_group_name"
        assert params["subscription_id"] == "subscription_id"
        assert params["region"] == "region"

    def test_remediate_success(self):
        client = Mock()
        client.network_security_groups.get.return_value = NetworkSecurityGroup(
            id="nsg",
            security_rules=[
                SecurityRule(
                    protocol="All",
                    access="Allow",
                    direction="Inbound",
                    source_address_prefix="*",
                    destination_port_ranges=["22-30", "3389"],
                ),
                SecurityRule(
                    protocol="All",
                    access="Allow",
                    direction="Inbound",
                    source_address_prefix="*",
                    destination_port_range="20-30",
                ),
                SecurityRule(
                    protocol="All",
                    access="Allow",
                    direction="Inbound",
                    source_address_prefix="*",
                    destination_port_range="22",
                ),
                SecurityRule(
                    protocol="All",
                    access="Allow",
                    direction="Inbound",
                    source_address_prefix="*",
                    destination_port_range="35",
                ),
            ],
        )

        action = NetworkSecurityGroupClosePort22()
        assert action.remediate(client, "security_group_name", "resource_group") == 0
        assert client.network_security_groups.create_or_update.call_count == 1

        call_args = client.network_security_groups.create_or_update.call_args
        updated_sg = call_args.args[2]
        security_rules = updated_sg.security_rules
        assert len(security_rules) == 3
        assert security_rules[0].destination_port_ranges == ["23-30","3389"]
        assert security_rules[1].destination_port_ranges == ["20-21", "23-30"]
        assert security_rules[1].destination_port_range is None
        assert security_rules[2].destination_port_range == "35"

    def test_remediate_with_exception(self):
        client = Mock()
        client.network_security_groups.create_or_update.side_effect = Exception
        action = NetworkSecurityGroupClosePort22()
        with pytest.raises(Exception):
            assert action.remediate(client, "security_group_id", "resource_group")
