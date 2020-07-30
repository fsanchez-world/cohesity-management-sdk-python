# -*- coding: utf-8 -*-
# Copyright 2020 Cohesity Inc.

import cohesity_management_sdk.models.app_instance_settings

class LaunchAppInstance(object):

    """Implementation of the 'LaunchAppInstance' model.

    Specifies app instance parameters.

    Attributes:
        app_uid (int|long):Specifies the app Id.
        app_version (int|long): Specifies the app version.
        creation_uid (string): Specifies unique identifier generated by the
            client to let the backend distinguish retries of the creation of
            the app instance.
        description (string): Specifies user configured description for the
            app instance.
        settings (AppInstanceSettings): Specifies launch settings.

    """

    # Create a mapping from Model property names to API property names
    _names = {
        "app_uid": 'appUid',
        "app_version": 'appVersion',
        "creation_uid": 'creationUid',
        "description": 'description',
        "settings":'settings'
    }

    def __init__(self,
                 app_uid=None,
                 app_version=None,
                 creation_uid=None,
                 description=None,
                 settings=None):
        """Constructor for the LaunchAppInstance class"""

        # Initialize members of the class
        self.app_uid = app_uid
        self.app_version = app_version
        self.creation_uid = creation_uid
        self.description = description
        self.settings = settings

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
        app_uid = dictionary.get('appUid')
        app_version = dictionary.get('appVersion')
        creation_uid = dictionary.get('creationUid')
        description = dictionary.get('description')
        settings = cohesity_management_sdk.models.app_instance_settings.AppInstanceSettings.from_dictionary(dictionary.get('settings')) if dictionary.get('settings') else None
        # Return an object of this model
        return cls(app_uid,
                   app_version,
                   creation_uid,
                   description,
                   settings)


