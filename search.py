# -*- coding: utf-8 -*-
# @Author   : TT
# @Email    : tt.jiaqi@gmail.com
# @File     : search.py
# @Time     : 2018/7/13 13:41

from shodan.client import Shodan
from shodan.exception import APIError
from collections import OrderedDict


class Shodan_sort(Shodan):

    def _request(self, function, params, service='shodan', method='get'):
        """General-purpose function to create web requests to SHODAN.

        Arguments:
            function  -- name of the function you want to execute
            params    -- dictionary of parameters for the function

        Returns
            A dictionary containing the function's results.

        """
        # Add the API key parameter automatically
        params['key'] = self.api_key

        # Determine the base_url based on which service we're interacting with
        base_url = {
            'shodan': self.base_url,
            'exploits': self.base_exploits_url,
        }.get(service, 'shodan')

        # Send the request
        try:
            if method.lower() == 'post':
                data = self._session.post(base_url + function, params)
            else:
                data = self._session.get(base_url + function, params=params)
        except:
            raise APIError('Unable to connect to Shodan')
        # Check that the API key wasn't rejected
        if data.status_code == 401:
            try:
                # Return the actual error message if the API returned valid JSON
                error = data.json()['error']
            except Exception as e:
                error = 'Invalid API key'

            raise APIError(error)

        # Parse the text into JSON
        try:
            data = data.json()
        except:
            raise APIError('Unable to parse JSON response')

        # Raise an exception if an error occurred
        if type(data) == dict and 'error' in data:
            raise APIError(data['error'])

        # Return the data
        return OrderedDict(data)
