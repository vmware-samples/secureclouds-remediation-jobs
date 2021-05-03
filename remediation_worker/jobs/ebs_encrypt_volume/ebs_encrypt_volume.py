# Copyright (c) 2021 VMware Inc.
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

import json
import logging
import sys

import boto3

logging.basicConfig(level=logging.INFO)


class EBSEncryptVolume:
    def parse(self, payload):
        """Parse payload received from Remediation Service.
        :param payload: JSON string containing parameters sent to the remediation job.
        :type payload: str.
        :returns: Dictionary of parsed parameters
        :rtype: dict
        :raises: Exception, JSONDecodeError
        """
        remediation_entry = json.loads(payload)
        notification_info = remediation_entry.get("notificationInfo", None)
        finding_info = notification_info.get("FindingInfo", None)

        volume_id = finding_info.get("ObjectId", None)
        region = finding_info.get("Region", None)

        if volume_id is None:
            logging.error("Missing parameters for 'VOLUME_ID'.")
            raise Exception("Missing parameters for 'VOLUME_ID'.")

        if region is None:
            logging.error("Missing parameters for 'REGION'.")
            raise Exception("Missing parameters for 'REGION'.")

        logging.info("parsed params")
        logging.info("  volume_id: %s", volume_id)

        return {
            "volume_id": volume_id,
            "region": region
        }

    def remediate(self, client, volume_id, region):
        """Encrypt EBS volume.  Any EC2 instances to which the volume is
           attached will be temporarily stopped.
        :param client: Instance of the AWS boto3 client.
        :param volume_id: The id of the EBS volume to encrypt.
        :type volume_id: str.
        :region: region where volume resides
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """

        # figure out where the volume is currently attached
        vol = boto3.resource('ec2', region_name=region).Volume(volume_id)
        attachments = self.stop_all_attached_instances(vol, region)
        
        # create an encrypted snapshot of the volume
        encrypted_snapshot = self.create_encrypted_snapshot(vol, region)

        # create an encrypted volume from the snapshot
        encrypted_volume = self.create_encrypted_volume(
            vol, encrypted_snapshot, client, region)

        # delete the encrypted snapshot we don't need any more
        logging.info("Deleting encrypted snapshot")
        encrypted_snapshot.delete()

        # re-attach the new encrypted volume where the old volume was
        if attachments:
           self.attach_encrypted_volume(encrypted_volume, attachments, client)

        # delete the old volume
        logging.info("Deleting unencrypted volume")
        vol.delete()

        # restart attached instances
        if attachments:
           self.start_ec2_instances(attachments, region)
        return 0

    def start_ec2_instances(self, attachments, region):
        """start ec2 that attached to the volume.
        :param attachments: EC2 list that attached to the volume.
        :param region: where the volume resides.
        """
        logging.info("Restarting EC2 instances")

        for a in attachments:
            instance = boto3.resource("ec2", region_name=region).Instance(a['InstanceId'])
            logging.info("   %s", instance.instance_id)
            instance.start()
            instance.wait_until_running()

    def attach_encrypted_volume(self, encrypted_volume, attachments, client):
        """attach the volume to ec2 list.
        :param attachments: EC2 list that attached to the volume.
        :param region: where the volume resides.
        :param client: Instance of the AWS boto3 client.
        """
        logging.info("Reattaching encrypted volume to EC2 host(s)")

        for a in attachments:
            logging.info("   %s: %s", a['InstanceId'], a['Device'])
            encrypted_volume.attach_to_instance(
                InstanceId=a['InstanceId'], Device=a['Device'])

        waiter = client.get_waiter('volume_in_use')
        waiter.wait(VolumeIds=[encrypted_volume.volume_id])
        logging.info("Encrypted volume attached")

    def create_encrypted_volume(self, vol, encrypted_snapshot, client, region):
        """create encrypted volume.
        :param vol: volume instant with correct type assigned
        :param encrypted_snapshot: encrypted snapshot id that is used to create the encrypted volume.
        :param client: Instance of the AWS boto3 client.
        """
        # options common to all volume types
        vol_opts = {
            'AvailabilityZone': vol.availability_zone,
            'Encrypted': True,
            'Size': vol.size,
            'SnapshotId': encrypted_snapshot.id,
            'VolumeType': vol.volume_type,
            'MultiAttachEnabled': vol.multi_attach_enabled,
        }

        # add type-specific options where necessary
        if vol.volume_type in ('gp3', 'io1', 'io2'):
            vol_opts['Iops'] = vol.iops

        if vol.volume_type == 'gp3':
            vol_opts['Throughput'] = vol.throughput

        if vol.tags:
            vol_opts['TagSpecifications'] = {
                'Tags': vol.tags
            }

        # create the volume and wait for it to become available
        response = client.create_volume(**vol_opts)
        waiter = client.get_waiter('volume_available')
        waiter.wait(VolumeIds=[response['VolumeId']])

        logging.info("Encrypted volume created: %s", response['VolumeId'])

        # return the boto3 resource representing the Volume
        return boto3.resource("ec2", region_name=region).Volume(response['VolumeId'])

    def create_encrypted_snapshot(self, vol, region):
        """create encrypted snapshot.
        :param vol: volume instant 
        :region: region that volume resides
        """
        logging.info("Creating temporary snapshot")
        snapshot = vol.create_snapshot(
            Description='temporary pre-encryption snapshot',
        )
        snapshot.wait_until_completed()

        logging.info("Creating encrypted copy of snapshot")
        response = snapshot.copy(
            Description=f"Temporary encrypted copy of {vol.volume_id} snapshot",
            Encrypted=True,
            SourceRegion=region)

        encrypted_snapshot = boto3.resource(
            'ec2', region_name=region).Snapshot(response['SnapshotId'])
        encrypted_snapshot.wait_until_completed()

        logging.info("Deleting temporary snapshot")
        snapshot.delete()

        return encrypted_snapshot

    def stop_all_attached_instances(self, vol, region):
        """stop EC2 instances that attached to the volume and detach the volume.
        :param vol: volume instant 
        :region: region that volume resides
        """
        attachments = []
        if vol.attachments:
            logging.info("volume has attachments")

            for a in vol.attachments:
                attachments.append(a)
                instance_id = a['InstanceId']

                logging.info("   instance-id: %s device: %s",
                             instance_id, a['Device'])

                instance = boto3.resource('ec2', region_name=region).Instance(instance_id)

                logging.info("   Stopping")
                instance.stop()
                instance.wait_until_stopped()

                logging.info("   Detaching volume")
                vol.detach_from_instance(InstanceId=instance_id)

        return attachments

    def run(self, args):
        """Run the remediation job.
        :param args: List of arguments provided to the job.
        :type args: list.
        :returns: int
        """
        params = self.parse(args[1])
        client = boto3.client("ec2", region_name=params['region'])

        logging.info(
            "acquired ec2 client and parsed params - starting remediation."
        )

        return self.remediate(client=client, **params)


if __name__ == "__main__":
    logging.info("ebs_encrypt_volume.py called - running now")
    obj = EBSEncryptVolume()
    obj.run(sys.argv)
