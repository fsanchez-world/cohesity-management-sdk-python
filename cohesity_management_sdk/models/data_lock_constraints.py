# -*- coding: utf-8 -*-
# Copyright 2023 Cohesity Inc.

class DataLockConstraints(object):

    """Implementation of the 'DataLockConstraints' model.

    Specifies the datalock retention type and expiry time when datalock expires


    Attributes:

        expiry_time_usecs (long|int): Specifies expiry time to keep Snapshots
            under datalock in a protection group.
        worm_retention_type (WormRetentionTypeEnum): Specifies WORM retention
            type for the snapshots. When a WORM retention type is specified,
            the snapshots of the Protection Jobs using this policy will be kept
            until the maximum of the snapshot retention time. During that time,
            the snapshots cannot be deleted. 'kNone' implies there is no WORM
            retention set. 'kCompliance' implies WORM retention is set for
            compliance reason. 'kAdministrative' implies WORM retention is set
            for administrative purposes.
    """


    # Create a mapping from Model property names to API property names
    _names = {
        "expiry_time_usecs":'expiryTimeUsecs',
        "worm_retention_type":'wormRetentionType',
    }
    def __init__(self,
                 expiry_time_usecs=None,
                 worm_retention_type=None,
            ):

        """Constructor for the DataLockConstraints class"""

        # Initialize members of the class
        self.expiry_time_usecs = expiry_time_usecs
        self.worm_retention_type = worm_retention_type

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
        expiry_time_usecs = dictionary.get('expiryTimeUsecs')
        worm_retention_type = dictionary.get('wormRetentionType')

        # Return an object of this model
        return cls(
            expiry_time_usecs,
            worm_retention_type
)