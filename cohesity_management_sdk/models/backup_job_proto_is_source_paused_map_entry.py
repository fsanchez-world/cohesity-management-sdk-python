# -*- coding: utf-8 -*-
# Copyright 2023 Cohesity Inc.


class BackupJobProto_IsSourcePausedMapEntry(object):

    """Implementation of the 'BackupJobProto_IsSourcePausedMapEntry' model.

    Specfies the key,value pair for the fleet tag.

    Attributes:
        key (int): Specifies the key for the fleet tag.
        value (bool): Specifies the value for the fleet tag.

    """

    # Create a mapping from Model property names to API property names
    _names = {
        "key": 'key',
        "value": 'value'
    }

    def __init__(self,
                 key=None,
                 value=None):
        """Constructor for the BackupJobProto_IsSourcePausedMapEntry class"""

        # Initialize members of the class
        self.key = key
        self.value = value


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
        key = dictionary.get('key', None)
        value = dictionary.get('value', None)

        # Return an object of this model
        return cls(key,
                   value)


