# -*- coding: utf-8 -*-
# Copyright 2020 Cohesity Inc.

import logging
from cohesity_management_sdk.api_helper import APIHelper
from cohesity_management_sdk.configuration import Configuration
from cohesity_management_sdk.controllers.base_controller import BaseController
from cohesity_management_sdk.http.auth.auth_manager import AuthManager
from cohesity_management_sdk.exceptions.request_error_error_exception import RequestErrorErrorException
from cohesity_management_sdk.exceptions.error_exception import ErrorException
from cohesity_management_sdk.models.ip_config import IpConfig
from cohesity_management_sdk.models.ip_unconfig import IpUnconfig

class IpController(BaseController):
    """A Controller to access Endpoints in the cohesity_management_sdk API."""
    def __init__(self, client=None, call_back=None):
        super(IpController, self).__init__(client, call_back)
        self.logger = logging.getLogger(__name__)

    def configure_ip(self, body):
        """Does a PUT request to /public/ip

        Configure the specfied IP settings on the Cohesity Cluster.

        Args:
            body (IpConfig): TODO: type description here. Example:

        Returns:
            IpConfig: Response from the API. Success

        Raises:
            APIException: When an error occurs while fetching the data from
                the remote API. This exception includes the HTTP Response
                code, an error message, and the HTTP body that was received in
                the request.

        """
        try:
            self.logger.info('configure_ip called.')

            # Validate required parameters
            self.logger.info(
                'Validating required parameters for configure_ip.')
            self.validate_parameters(body=body)

            # Prepare query URL
            self.logger.info(
                'Preparing query URL for configure_ip.')
            _url_path = '/public/ip'
            _query_builder = Configuration.get_base_uri()
            _query_builder += _url_path
            _query_url = APIHelper.clean_url(_query_builder)

            # Prepare headers
            self.logger.info('Preparing headers for configure_ip.')
            _headers = {
                'accept': 'application/json',
                'content-type': 'application/json; charset=utf-8'
            }

            # Prepare and execute request
            self.logger.info(
                'Preparing and executing request for configure_ip.'
            )
            _request = self.http_client.put(
                _query_url,
                headers=_headers,
                parameters=APIHelper.json_serialize(body))
            AuthManager.apply(_request)
            _context = self.execute_request(_request,
                                            name='configure_ip')

            # Endpoint and global error handling using HTTP status codes.
            self.logger.info(
                'Validating response for configure_ip.')
            if _context.response.status_code == 0:
                raise RequestErrorErrorException('Error', _context)
            self.validate_response(_context)

            # Return appropriate type
            return APIHelper.json_deserialize(
                _context.response.raw_body, IpConfig.from_dictionary)

        except Exception as e:
            self.logger.error(e, exc_info=True)
            raise

    def unconfigure_ip(self, body=None):
        """Does a DELETE request to /public/ip.

        Returns error if op fails.

        Args:
            body (IpUnconfig, optional): update user quota
                params.

        Returns:
            void: Response from the API. No Content

        Raises:
            APIException: When an error occurs while fetching the data from
                the remote API. This exception includes the HTTP Response
                code, an error message, and the HTTP body that was received in
                the request.

        """
        try:
            self.logger.info('unconfigure_ip called.')

            # Prepare query URL
            self.logger.info(
                'Preparing query URL for unconfigure_ip.')
            _url_path = '/public/ip'
            _query_builder = Configuration.get_base_uri()
            _query_builder += _url_path
            _query_url = APIHelper.clean_url(_query_builder)

            # Prepare headers
            self.logger.info('Preparing headers for unconfigure_ip.')
            _headers = {'content-type': 'application/json; charset=utf-8'}

            # Prepare and execute request
            self.logger.info(
                'Preparing and executing request for unconfigure_ip.')
            _request = self.http_client.delete(
                _query_url,
                headers=_headers,
                parameters=APIHelper.json_serialize(body))
            AuthManager.apply(_request)
            _context = self.execute_request(_request,
                                            name='unconfigure_ip')

            # Endpoint and global error handling using HTTP status codes.
            self.logger.info(
                'Validating response for unconfigure_ip.')
            if _context.response.status_code == 0:
                raise RequestErrorErrorException('Error', _context)
            self.validate_response(_context)

        except Exception as e:
            self.logger.error(e, exc_info=True)
            raise
