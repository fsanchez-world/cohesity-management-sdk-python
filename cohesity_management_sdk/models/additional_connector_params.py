# -*- coding: utf-8 -*-
# Copyright 2023 Cohesity Inc.

import cohesity_management_sdk.models.o365_region_proto
import cohesity_management_sdk.models.registered_entity_sfdc_params


class AdditionalConnectorParams(object):

    """Implementation of the 'AdditionalConnectorParams' model.

    Message that encapsulates the additional connector params to establish a
    connection with a particular environment.


    Attributes:

        max_vmware_http_sessions (int): Max http sessions per context for
            VMWare vAPI calls.
        o365_emulator_entity_info (string): A token used only in O365 Emulator
            identifying the information of number of Users, Sites, Groups,
            Teams & Public Folders and their ids.
        o365_region (O365RegionProto): Optional o365_region proto to store the
            region info to be used while making ews/graph api calls in o365
            adapter.
        registered_entity_sfdc_params (RegisteredEntitySfdcParams):
            RegisteredEntitySfdcParams contains soap_endpoint_url and
            metadata_endpoint_url which are needed for connecting to Sfdc in
            connector params. TODO: Fill and send these values from Iris to
            magneto.
        use_get_searchable_mailboxes_api (bool): Wheather to use
            GetSearchableMailboxes EWS API while descovering User Mailboxes or
            not.
        use_outlook_ews_oauth (bool): Whether OAuth should be used for
            authentication with EWS API (outlook backup), applicable only for
            Exchange Online.
    """


    # Create a mapping from Model property names to API property names
    _names = {
        "max_vmware_http_sessions":'maxVmwareHttpSessions',
        "o365_emulator_entity_info":'o365EmulatorEntityInfo',
        "o365_region":'o365Region',
        "registered_entity_sfdc_params":'registeredEntitySfdcParams',
        "use_get_searchable_mailboxes_api":'useGetSearchableMailboxesApi',
        "use_outlook_ews_oauth":'useOutlookEwsOauth',
    }
    def __init__(self,
                 max_vmware_http_sessions=None,
                 o365_emulator_entity_info=None,
                 o365_region=None,
                 registered_entity_sfdc_params=None,
                 use_get_searchable_mailboxes_api=None,
                 use_outlook_ews_oauth=None,
            ):

        """Constructor for the AdditionalConnectorParams class"""

        # Initialize members of the class
        self.max_vmware_http_sessions = max_vmware_http_sessions
        self.o365_emulator_entity_info = o365_emulator_entity_info
        self.o365_region = o365_region
        self.registered_entity_sfdc_params = registered_entity_sfdc_params
        self.use_get_searchable_mailboxes_api = use_get_searchable_mailboxes_api
        self.use_outlook_ews_oauth = use_outlook_ews_oauth

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
        max_vmware_http_sessions = dictionary.get('maxVmwareHttpSessions')
        o365_emulator_entity_info = dictionary.get('o365EmulatorEntityInfo')
        o365_region = cohesity_management_sdk.models.o365_region_proto.O365RegionProto.from_dictionary(dictionary.get('o365Region')) if dictionary.get('o365Region') else None
        registered_entity_sfdc_params = cohesity_management_sdk.models.registered_entity_sfdc_params.RegisteredEntitySfdcParams.from_dictionary(dictionary.get('registeredEntitySfdcParams')) if dictionary.get('registeredEntitySfdcParams') else None
        use_get_searchable_mailboxes_api = dictionary.get('useGetSearchableMailboxesApi')
        use_outlook_ews_oauth = dictionary.get('useOutlookEwsOauth')

        # Return an object of this model
        return cls(
            max_vmware_http_sessions,
            o365_emulator_entity_info,
            o365_region,
            registered_entity_sfdc_params,
            use_get_searchable_mailboxes_api,
            use_outlook_ews_oauth
)