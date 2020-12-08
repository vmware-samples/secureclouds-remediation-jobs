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
from remediation_worker.jobs.azure_sql_threat_detection_on_server.azure_sql_threat_detection_on_server import (
    EnableSqlServerThreatProtection,
)


@pytest.fixture
def valid_payload():
    return """
{
    "notificationInfo": {
        "RuleId": "5c8c268d7a550e1fb6560cc0",
        "Service": "Sql",
        "FindingInfo": {
            "FindingId": "86c63989-4193-4785-b010-3fafb64e9d83",
            "ObjectId": "sql_server_name",
            "ObjectChain": "{\\"cloudAccountId\\":\\"subscription_id\\",\\"entityId\\":\\"Azure.Sql.d687b1a3-9b78-43b1-a17b-7de297fd1fce.resource_group_name.Server.sql_server_name\\",\\"entityName\\":\\"sql_server_name\\",\\"entityType\\":\\"Azure.Sql.Server\\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"d687b1a3-9b78-43b1-a17b-7de297fd1fce\\",\\"provider\\":\\"Azure\\",\\"region\\":\\"eastus\\",\\"service\\":\\"Sql\\", \\"properties\\":[{\\"name\\":\\"ResourceGroup\\",\\"stringV\\":\\"resource_group_name\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestEnableSqlServerThreatDetection(object):
    def test_parse_payload(self, valid_payload):
        params = EnableSqlServerThreatProtection().parse(valid_payload)
        assert params["sql_server_name"] == "sql_server_name"
        assert params["resource_group_name"] == "resource_group_name"
        assert params["subscription_id"] == "subscription_id"
        assert params["region"] == "region"

    def test_remediate_success(self):
        client = Mock()
        action = EnableSqlServerThreatProtection()
        assert action.remediate(client, "resource_group", "sql_server_name") == 0
        assert client.server_security_alert_policies.create_or_update.call_count == 1

        call_args = client.server_security_alert_policies.create_or_update.call_args
        updated_sql_server_parameters = call_args[1]["parameters"]
        assert updated_sql_server_parameters.state == "Enabled"

    def test_remediate_with_exception(self):
        client = Mock()
        client.server_security_alert_policies.create_or_update.side_effect = Exception
        action = EnableSqlServerThreatProtection()
        with pytest.raises(Exception):
            assert action.remediate(client, "security_group_id", "resource_group")
