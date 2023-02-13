# -*- coding: utf-8 -*-
# Copyright 2023 Cohesity Inc.

import cohesity_management_sdk.models.granularity_bucket
import cohesity_management_sdk.models.retention_policy_proto

class ExtendedRetentionPolicyProto(object):

    """Implementation of the 'ExtendedRetentionPolicyProto' model.

    Message that specifies additional retention policies to apply to backup
    snapshots.

    Attributes:
        backup_type (int): The backup type to which this extended retention
            applies to. If this is not set, the extended retention will be
            applicable to all non-log backup types.
            Currently, the only value that can be set here is kFull (Magneto will
            return an error if it is set to anything else).
        copy_partially_successful_run (bool): If this is false, then only
            snapshots from the first completely successful run in the given
            time granularity will be considered for being copied. If this is
            true, then snapshots from the first partially successful run will
            also be considered eligible.
        granularity_bucket (GranularityBucket): The granularity bucket
            frequency which determines the backup snapshots that this extended
            retention policy applies to.
        id (string): This id uniquely identifies this entry in the
            ProtectionPolicyProto. If this message is from global policy, this
            id is generated by Helios. Otherwise, it is generated by Iris.
            Magneto treats this as an opaque identifier.
        retention_policy (RetentionPolicyProto): Message that specifies the
            retention policy for backup snapshots.

    """

    # Create a mapping from Model property names to API property names
    _names = {
        "backup_type":'backupType',
        "copy_partially_successful_run":'copyPartiallySuccessfulRun',
        "granularity_bucket":'granularityBucket',
        "id":'id',
        "retention_policy":'retentionPolicy'
    }

    def __init__(self,
                 backup_type=None,
                 copy_partially_successful_run=None,
                 granularity_bucket=None,
                 id=None,
                 retention_policy=None):
        """Constructor for the ExtendedRetentionPolicyProto class"""

        # Initialize members of the class
        self.backup_type = backup_type
        self.copy_partially_successful_run = copy_partially_successful_run
        self.granularity_bucket = granularity_bucket
        self.id = id
        self.retention_policy = retention_policy


    @classmethod
    def from_dictionary(cls,
                        dictionary):
        """Creates an instance of this model from a dictionary

        Args:
            dictionary (dictionary): A dictionary representation of the object as
            obtained from the deserialization of the server's response. The keys
            MUST match property names in the API description.

        Returns:
            object: An instance of this structure class.

        """
        if dictionary is None:
            return None

        # Extract variables from the dictionary
        backup_type = dictionary.get('backupType')
        copy_partially_successful_run = dictionary.get('copyPartiallySuccessfulRun')
        granularity_bucket = cohesity_management_sdk.models.granularity_bucket.GranularityBucket.from_dictionary(dictionary.get('granularityBucket')) if dictionary.get('granularityBucket') else None
        id = dictionary.get('id')
        retention_policy = cohesity_management_sdk.models.retention_policy_proto.RetentionPolicyProto.from_dictionary(dictionary.get('retentionPolicy')) if dictionary.get('retentionPolicy') else None

        # Return an object of this model
        return cls(backup_type,
                   copy_partially_successful_run,
                   granularity_bucket,
                   id,
                   retention_policy)


