# -*- coding: utf-8 -*-
# Copyright 2023 Cohesity Inc.

import cohesity_management_sdk.models.filtering_policy_proto


class OutlookBackupEnvParams(object):

    """Implementation of the 'OutlookBackupEnvParams' model.

    Message to capture any additional backup params for Outlook within
    Office365 environment.


    Attributes:

        filtering_policy (FilteringPolicyProto): The filtering policy describes
            which paths within a mailbox should be excluded within the backup.
            If this is not specified, then the entire Outlook mailbox will be
            backed up.
        should_backup_mailbox (bool): Specifies whether the mailbox for all the
            Office365 Users present in the protection job should be backed up.
    """


    # Create a mapping from Model property names to API property names
    _names = {
        "filtering_policy":'filteringPolicy',
        "should_backup_mailbox":'shouldBackupMailbox',
    }
    def __init__(self,
                 filtering_policy=None,
                 should_backup_mailbox=None,
            ):

        """Constructor for the OutlookBackupEnvParams class"""

        # Initialize members of the class
        self.filtering_policy = filtering_policy
        self.should_backup_mailbox = should_backup_mailbox

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
        filtering_policy = cohesity_management_sdk.models.filtering_policy_proto.FilteringPolicyProto.from_dictionary(dictionary.get('filteringPolicy')) if dictionary.get('filteringPolicy') else None
        should_backup_mailbox = dictionary.get('shouldBackupMailbox')

        # Return an object of this model
        return cls(
            filtering_policy,
            should_backup_mailbox
)