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
from remediation_worker.jobs.security_group_close_port_3389.security_group_close_port_3389 import (
    SecurityGroupClosePort3389,
)


@pytest.fixture
def valid_payload1():
    return """
        {
            "notificationInfo": {
                "FindingInfo": {
                    "ObjectId": "security_group_id"
                }
            }
        }
    """


class TestSecurityGroupClosePort3389(object):
    def test_parse_payload(self, valid_payload1):
        obj = SecurityGroupClosePort3389()
        param, region = obj.parse(valid_payload1)
        assert "security_group_id" in param

    def test_remediate_with_no_rule(self):
        class TestClient(object):
            def revoke_security_group_ingress(self, **kwargs):
                raise ClientError(
                    {
                        "Error": {
                            "Code": "NotFound",
                            "Message": "InvalidPermission.NotFound",
                        }
                    },
                    "TestSecurityGroupClosePort3389",
                )

        client = TestClient()
        action = SecurityGroupClosePort3389()
        assert action.remediate(client, "security_group_id") == 0

    def test_remediate_success(self):
        class TestClient(object):
            def revoke_security_group_ingress(self, **kwargs):
                return None

        client = TestClient()
        action = SecurityGroupClosePort3389()
        assert action.remediate(client, "security_group_id") == 0

    def test_remediate_with_exception(self):
        class TestClient(object):
            def revoke_security_group_ingress(self, **kwargs):
                raise RuntimeError("Exception")

        client = TestClient()
        action = SecurityGroupClosePort3389()
        with pytest.raises(Exception):
            assert action.remediate(client, "security_group_id")
