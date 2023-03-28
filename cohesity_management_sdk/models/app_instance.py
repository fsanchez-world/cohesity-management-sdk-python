# -*- coding: utf-8 -*-
# Copyright 2023 Cohesity Inc.

import cohesity_management_sdk.models.app_instance_settings
import cohesity_management_sdk.models.node_port
import cohesity_management_sdk.models.user_ssh_key
import cohesity_management_sdk.models.vm_group


class AppInstance(object):

    """Implementation of the 'AppInstance' model.

    AppInstance provides application instance's information.


    Attributes:

        app_access_token (string): Specifies the token to access with the app.
        app_instance_id (long|int): Specifies unique id across all instances of
            all apps.
        app_name (string): Specifies name of the app that is launched in this
            instance.
        app_uid (long|int): Specifies id of the app that is launched in this
            instance.
        app_version (long|int): Specifies the version of the app that is
            launched in this instance.
        created_time_usecs (long|int): Specifies timestamp (in microseconds)
            when the app instance was first created.
        creation_uid (string): Specifies a unique identifier generated by the
            client to let the backend identify retries of the app launch
            request.
        deployment_parameters (string): Deployment parameters used to launch
            the app instance.
        description (string): Specifies user configured description for the app
            instance.
        dev_version (string): Specifies version of the app provided by the
            developer.
        duration_usecs (long|int): Specifies duration (in microseconds) for
            which the app instance has run.
        exposed_node_ports (list of NodePort): Specifies list of nodeports
            exposed by app instance.
        health_detail (string): Specifies the reason the app instance is
            unhealthy. Only set if app instance is unhealthy.
        health_status (int): Specifies the current health status of the app
            instance.
        https_ui (bool): Specifies app ui http config. If set to true, the
            App's UI uses https. Otherwise it uses http.
        namespace (string): TODO: Type description here.
        node_ip (string): Specifies the ip of the node which can be used to
            contact app instance external services.
        node_port (int): Specifies the node port on which the app instance
            services external requests.
        settings (AppInstanceSettings): Specifies settings used to launch an
            app instance.
        state (StateAppInstanceEnum): Specifies the current state of the app
            instance. Specifies operational status of an app instance.
            kInitializing - The app instance has been launched or resumed, but
            is not fully running yet. kRunning - The app instance is running.
            Check health_status for the actual health. kPausing - The app
            instance is being paused. kPaused - The app instance has been
            paused. kTerminating - The app instance is being terminated.
            kTerminated -  The app instance has been terminated. kFailed - The
            app instance has failed due to an unrecoverable error.
        state_detail (string): Specifies the failure reason when the app
            instance's state is kFailed.
        ui_cluster_ip_svc_addr (string): Specifies UI Tag ClusterIP Service Ip
            Address
        ui_cluster_ip_svc_port (int): Specifies UI Tag ClusterIP Service Port
        upgradable_newer_version_present (bool): Specifies if the app instance
            is upgradable
        user_ssh_key (UserSshKey): Specifies username and corresponding ssh key
            to be inserted into the VMs.
        vm_groups (list of VmGroup): Specifies list of all VM groups for this
            application. Each VM group contains a list of VMs. Information
            needed for UI like the nodePort, the port type etc. is stored for
            each VM.
    """


    # Create a mapping from Model property names to API property names
    _names = {
        "app_access_token":'appAccessToken',
        "app_instance_id":'appInstanceId',
        "app_name":'appName',
        "app_uid":'appUid',
        "app_version":'appVersion',
        "created_time_usecs":'createdTimeUsecs',
        "creation_uid":'creationUid',
        "deployment_parameters":'deploymentParameters',
        "description":'description',
        "dev_version":'devVersion',
        "duration_usecs":'durationUsecs',
        "exposed_node_ports":'exposedNodePorts',
        "health_detail":'healthDetail',
        "health_status":'healthStatus',
        "https_ui":'httpsUi',
        "namespace":'namespace',
        "node_ip":'nodeIp',
        "node_port":'nodePort',
        "settings":'settings',
        "state":'state',
        "state_detail":'stateDetail',
        "ui_cluster_ip_svc_addr":'uiClusterIPSvcAddr',
        "ui_cluster_ip_svc_port":'uiClusterIPSvcPort',
        "upgradable_newer_version_present":'upgradableNewerVersionPresent',
        "user_ssh_key":'userSshKey',
        "vm_groups":'vmGroups',
    }
    def __init__(self,
                 app_access_token=None,
                 app_instance_id=None,
                 app_name=None,
                 app_uid=None,
                 app_version=None,
                 created_time_usecs=None,
                 creation_uid=None,
                 deployment_parameters=None,
                 description=None,
                 dev_version=None,
                 duration_usecs=None,
                 exposed_node_ports=None,
                 health_detail=None,
                 health_status=None,
                 https_ui=None,
                 namespace=None,
                 node_ip=None,
                 node_port=None,
                 settings=None,
                 state=None,
                 state_detail=None,
                 ui_cluster_ip_svc_addr=None,
                 ui_cluster_ip_svc_port=None,
                 upgradable_newer_version_present=None,
                 user_ssh_key=None,
                 vm_groups=None,
            ):

        """Constructor for the AppInstance class"""

        # Initialize members of the class
        self.app_access_token = app_access_token
        self.app_instance_id = app_instance_id
        self.app_name = app_name
        self.app_uid = app_uid
        self.app_version = app_version
        self.created_time_usecs = created_time_usecs
        self.creation_uid = creation_uid
        self.deployment_parameters = deployment_parameters
        self.description = description
        self.dev_version = dev_version
        self.duration_usecs = duration_usecs
        self.exposed_node_ports = exposed_node_ports
        self.health_detail = health_detail
        self.health_status = health_status
        self.https_ui = https_ui
        self.namespace = namespace
        self.node_ip = node_ip
        self.node_port = node_port
        self.settings = settings
        self.state = state
        self.state_detail = state_detail
        self.ui_cluster_ip_svc_addr = ui_cluster_ip_svc_addr
        self.ui_cluster_ip_svc_port = ui_cluster_ip_svc_port
        self.upgradable_newer_version_present = upgradable_newer_version_present
        self.user_ssh_key = user_ssh_key
        self.vm_groups = vm_groups

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
        app_access_token = dictionary.get('appAccessToken')
        app_instance_id = dictionary.get('appInstanceId')
        app_name = dictionary.get('appName')
        app_uid = dictionary.get('appUid')
        app_version = dictionary.get('appVersion')
        created_time_usecs = dictionary.get('createdTimeUsecs')
        creation_uid = dictionary.get('creationUid')
        deployment_parameters = dictionary.get('deploymentParameters')
        description = dictionary.get('description')
        dev_version = dictionary.get('devVersion')
        duration_usecs = dictionary.get('durationUsecs')
        exposed_node_ports = None
        if dictionary.get('exposedNodePorts') != None:
            exposed_node_ports = list()
            for structure in dictionary.get('exposedNodePorts'):
                exposed_node_ports.append(cohesity_management_sdk.models.node_port.NodePort.from_dictionary(structure))
        health_detail = dictionary.get('healthDetail')
        health_status = dictionary.get('healthStatus')
        https_ui = dictionary.get('httpsUi')
        namespace = dictionary.get('namespace')
        node_ip = dictionary.get('nodeIp')
        node_port = dictionary.get('nodePort')
        settings = cohesity_management_sdk.models.app_instance_settings.AppInstanceSettings.from_dictionary(dictionary.get('settings')) if dictionary.get('settings') else None
        state = dictionary.get('state')
        state_detail = dictionary.get('stateDetail')
        ui_cluster_ip_svc_addr = dictionary.get('uiClusterIPSvcAddr')
        ui_cluster_ip_svc_port = dictionary.get('uiClusterIPSvcPort')
        upgradable_newer_version_present = dictionary.get('upgradableNewerVersionPresent')
        user_ssh_key = cohesity_management_sdk.models.user_ssh_key.UserSshKey.from_dictionary(dictionary.get('userSshKey')) if dictionary.get('userSshKey') else None
        vm_groups = None
        if dictionary.get('vmGroups') != None:
            vm_groups = list()
            for structure in dictionary.get('vmGroups'):
                vm_groups.append(cohesity_management_sdk.models.vm_group.VmGroup.from_dictionary(structure))

        # Return an object of this model
        return cls(
            app_access_token,
            app_instance_id,
            app_name,
            app_uid,
            app_version,
            created_time_usecs,
            creation_uid,
            deployment_parameters,
            description,
            dev_version,
            duration_usecs,
            exposed_node_ports,
            health_detail,
            health_status,
            https_ui,
            namespace,
            node_ip,
            node_port,
            settings,
            state,
            state_detail,
            ui_cluster_ip_svc_addr,
            ui_cluster_ip_svc_port,
            upgradable_newer_version_present,
            user_ssh_key,
            vm_groups
)