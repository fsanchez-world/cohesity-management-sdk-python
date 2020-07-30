# -*- coding: utf-8 -*-
# Copyright 2020 Cohesity Inc.


class UnRegisterApplicationServersParameters(object):

    """Implementation of the 'UnRegisterApplicationServersParameters' model.

    Specifies the parameters required to unregister
    Application Servers running in a Protection Source.

    Attributes:
        applications (list of ApplicationEnum): Specifies the types of
            applications such as 'kSQL', 'kExchange' running on the Protection
            Source. overrideDescription: true Supported environment types such
            as 'kView', 'kSQL', 'kVMware', etc. NOTE: 'kPuppeteer' refers to
            Cohesity's Remote Adapter. 'kVMware' indicates the VMware
            Protection Source environment. 'kHyperV' indicates the HyperV
            Protection Source environment. 'kSQL' indicates the SQL Protection
            Source environment. 'kView' indicates the View Protection Source
            environment. 'kPuppeteer' indicates the Cohesity's Remote Adapter.
            'kPhysical' indicates the physical Protection Source environment.
            'kPure' indicates the Pure Storage Protection Source environment.
            'Nimble' indicates the Nimble Storage Protection Source
            environment. 'kAzure' indicates the Microsoft's Azure Protection
            Source environment. 'kNetapp' indicates the Netapp Protection
            Source environment. 'kAgent' indicates the Agent Protection Source
            environment. 'kGenericNas' indicates the Generic Network Attached
            Storage Protection Source environment. 'kAcropolis' indicates the
            Acropolis Protection Source environment. 'kPhsicalFiles' indicates
            the Physical Files Protection Source environment. 'kIsilon'
            indicates the Dell EMC's Isilon Protection Source environment.
            'kGPFS' indicates IBM's GPFS Protection Source environment. 'kKVM'
            indicates the KVM Protection Source environment. 'kAWS' indicates
            the AWS Protection Source environment. 'kExchange' indicates the
            Exchange Protection Source environment. 'kHyperVVSS' indicates the
            HyperV VSS Protection Source environment. 'kOracle' indicates the
            Oracle Protection Source environment. 'kGCP' indicates the Google
            Cloud Platform Protection Source environment. 'kFlashBlade'
            indicates the Flash Blade Protection Source environment.
            'kAWSNative' indicates the AWS Native Protection Source
            environment. 'kO365' indicates the Office 365
            Protection Source environment. 'kO365Outlook' indicates Office 365
            outlook Protection Source environment. 'kHyperFlex' indicates the
            Hyper Flex Protection Source environment. 'kGCPNative' indicates
            the GCP Native Protection Source environment. 'kAzureNative'
            indicates the Azure Native Protection Source environment.
            'kKubernetes' indicates a Kubernetes Protection Source
            environment. 'kElastifile' indicates Elastifile Protection Source
            environment. 'kAD' indicates Active Directory Protection Source
            environment. 'kRDSSnapshotManager' indicates AWS RDS Protection
            Source environment.

    """

    # Create a mapping from Model property names to API property names
    _names = {
        "applications":'applications'
    }

    def __init__(self,
                 applications=None):
        """Constructor for the UnRegisterApplicationServersParameters class"""

        # Initialize members of the class
        self.applications = applications


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
        applications = dictionary.get('applications')

        # Return an object of this model
        return cls(applications)


