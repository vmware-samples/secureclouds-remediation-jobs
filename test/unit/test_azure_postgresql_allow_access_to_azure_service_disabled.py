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
from remediation_worker.jobs.azure_postgresql_allow_access_to_azure_service_disabled.azure_postgresql_allow_access_to_azure_service_disabled import (
    DisableAzureServicesAccess,
)


@pytest.fixture
def valid_payload():
    return """
{
    "notificationInfo": {
        "RuleId": "5c8c268d7a550e1fb6560cc0",
        "Service": "PostgreSQL",
        "FindingInfo": {
            "FindingId": "d3bb1d9a-fe52-4458-9935-47183f140e6b",
            "ObjectId": "postgresqlwnuuobrlrwngs",
            "ObjectChain": "{\\"cloudAccountId\\":\\"subscription_id\\",\\"entityId\\":\\"Azure.PostgreSQL.d687b1a3-9b78-43b1-a17b-7de297fd1fce.integration-tests-postgresql-b3wx.Server.postgresqlwnuuobrlrwngs\\",\\"entityName\\":\\"postgresqlwnuuobrlrwngs\\",\\"entityType\\":\\"Azure.PostgreSQL.Server\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"d687b1a3-9b78-43b1-a17b-7de297fd1fce\\",\\"provider\\":\\"Azure\\",\\"region\\":\\"eastus\\",\\"service\\":\\"PostgreSQL\\", \\"properties\\":[{\\"name\\":\\"ResourceGroup\\",\\"stringV\\":\\"resource_group_name\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestEnableSqlDataEncryption(object):
    def test_parse_payload(self, valid_payload):
        params = DisableAzureServicesAccess().parse(valid_payload)
        assert params["postgre_server_name"] == "postgresqlwnuuobrlrwngs"
        assert params["resource_group_name"] == "resource_group_name"
        assert params["subscription_id"] == "subscription_id"
        assert params["region"] == "region"

    def test_remediate_success(self):
        client = Mock()
        action = DisableAzureServicesAccess()
        assert action.remediate(client, "resource_group", "postgre_server_name") == 0
        assert client.firewall_rules.begin_delete.call_count == 1

        call_args = client.firewall_rules.begin_delete.call_args
        firewall_rule_name = call_args[1]["firewall_rule_name"]
        assert firewall_rule_name == "AllowAllWindowsAzureIps"

    def test_remediate_with_exception(self):
        client = Mock()
        client.firewall_rules.begin_delete.side_effect = Exception
        action = DisableAzureServicesAccess()
        with pytest.raises(Exception):
            assert action.remediate(client, "security_group_id", "resource_group")
