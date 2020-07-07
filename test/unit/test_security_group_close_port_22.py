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
from botocore.exceptions import ClientError
from remediation_worker.jobs.security_group_close_port_22.security_group_close_port_22 import (
    SecurityGroupClosePort22,
)


@pytest.fixture
def valid_payload1():
    return """
{
    "notificationInfo": {
        "FindingInfo": {
            "ObjectId": "security_group_id",
            "Region": "region"
        }
    }
}
"""


class TestSecurityGroupClosePort22(object):
    def test_parse_payload(self, valid_payload1):
        params = SecurityGroupClosePort22().parse(valid_payload1)
        assert params['security_group_id'] == 'security_group_id'
        assert params['region'] == 'region'

    def test_remediate_success(self):
        class TestClient(object):
            def revoke_security_group_ingress(self, **kwargs):
                return None

        client = TestClient()
        action = SecurityGroupClosePort22()
        assert action.remediate(client, "security_group_id") == 0

    def test_remediate_with_exception(self):
        class TestClient(object):
            def revoke_security_group_ingress(self, **kwargs):
                raise RuntimeError("Exception")

        client = TestClient()
        action = SecurityGroupClosePort22()
        with pytest.raises(Exception):
            assert action.remediate(client, "security_group_id")
