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

from remediation_worker.jobs.azure_storage_account_allow_https_traffic_only.azure_storage_account_allow_https_traffic_only import (
    StorageAccountAllowHttpsTrafficOnly,
)


@pytest.fixture
def valid_payload():
    return """
{
    "notificationInfo": {
        "RuleId": "5c8c269a7a550e1fb6560cdb",
        "Service": "Storage",
        "FindingInfo": {
            "FindingId": "e1606076-d55c-42c5-9ca7-93e933b1e672",
            "ObjectId": "storage_account_name",
            "ObjectChain": "{\\"cloudAccountId\\":\\"subscription_id\\",\\"entityId\\":\\"Azure.Storage.d687b1a3-9b78-43b1-a17b-7de297fd1fce.resource_group_name.StorageAccount.testingresourcename\\",\\"entityName\\":\\"testingresourcename\\",\\"entityType\\":\\"Azure.Storage.StorageAccount\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"d687b1a3-9b78-43b1-a17b-7de297fd1fce\\",\\"provider\\":\\"Azure\\",\\"region\\":\\"eastus\\",\\"service\\":\\"Storage\\", \\"properties\\":[{\\"name\\":\\"ResourceGroup\\",\\"stringV\\":\\"resource_group_name\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestStorageAccountAllowHttpsTrafficOnly(object):
    def test_parse_payload(self, valid_payload):
        params = StorageAccountAllowHttpsTrafficOnly().parse(valid_payload)
        assert params["account_name"] == "storage_account_name"
        assert params["resource_group_name"] == "resource_group_name"
        assert params["subscription_id"] == "subscription_id"
        assert params["region"] == "region"

    def test_remediate_success(self):
        client = Mock()
        action = StorageAccountAllowHttpsTrafficOnly()
        assert action.remediate(client, "security_group_name", "resource_group") == 0
        assert client.storage_accounts.update.call_count == 1

        call_args = client.storage_accounts.update.call_args
        update_param = call_args[1]["parameters"]
        assert update_param.enable_https_traffic_only == True

    def test_remediate_with_exception(self):
        client = Mock()
        client.network_security_groups.create_or_update.side_effect = Exception
        action = StorageAccountAllowHttpsTrafficOnly()
        with pytest.raises(Exception):
            assert action.remediate(client, "security_group_id", "resource_group")
