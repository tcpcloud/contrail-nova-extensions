# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutronclient.common import exceptions as neutron_client_exc
from nova import exception
from nova.network import model as network_model
from nova.network import neutronv2
from nova.network.neutronv2.api import API as neutronv2_api
from nova.openstack.common import excutils
from nova.openstack.common.gettextutils import _
from nova.openstack.common import log as logging

LOG = logging.getLogger(__name__)
class API(neutronv2_api):
    """contrail network API class Derived from nova neutronv2 API class."""

    def __init__(self):
        super(API, self).__init__()

    def validate_networks(self, context, requested_networks, num_instances):
        """Validate that the tenant can use the requested networks.

        Return the number of instances than can be successfully allocated
        with the requested network configuration.
        """
        LOG.debug(_('validate_networks() for %s'),
                  requested_networks)

        neutron = neutronv2.get_client(context)
        ports_needed_per_instance = 0

        if not requested_networks:
            nets = self._get_available_networks(context, context.project_id,
                                                neutron=neutron)
            if len(nets) > 1:
                # Attaching to more than one network by default doesn't
                # make sense, as the order will be arbitrary and the guest OS
                # won't know which to configure
                msg = _("Multiple possible networks found, use a Network "
                         "ID to be more specific.")
                raise exception.NetworkAmbiguous(msg)
            else:
                ports_needed_per_instance = 1

        else:
            net_ids = []

            for (net_id, _i, port_id) in requested_networks:
                if port_id:
                    try:
                        port = neutron.show_port(port_id).get('port')
                    except neutronv2.exceptions.NeutronClientException as e:
                        if e.status_code == 404:
                            port = None
                        else:
                            with excutils.save_and_reraise_exception():
                                LOG.exception(_("Failed to access port %s"),
                                              port_id)
                    if not port:
                        raise exception.PortNotFound(port_id=port_id)
                    if port.get('device_id', None):
                        raise exception.PortInUse(port_id=port_id)
                    if not port.get('fixed_ips'):
                        raise exception.PortRequiresFixedIP(port_id=port_id)
                    net_id = port['network_id']
                else:
                    ports_needed_per_instance += 1

                if net_id in net_ids:
                    raise exception.NetworkDuplicated(network_id=net_id)
                net_ids.append(net_id)

            # Now check to see if all requested networks exist
            nets = self._get_available_networks(context,
                                    context.project_id, net_ids,
                                    neutron=neutron)
            for net in nets:
                if not net.get('subnets'):
                    raise exception.NetworkRequiresSubnet(
                        network_uuid=net['id'])

            if len(nets) != len(net_ids):
                requsted_netid_set = set(net_ids)
                returned_netid_set = set([net['id'] for net in nets])
                lostid_set = requsted_netid_set - returned_netid_set
                id_str = ''
                for _id in lostid_set:
                    id_str = id_str and id_str + ', ' + _id or _id
                raise exception.NetworkNotFound(network_id=id_str)

        # Note(PhilD): Ideally Nova would create all required ports as part of
        # network validation, but port creation requires some details
        # from the hypervisor.  So we just check the quota and return
        # how many of the requested number of instances can be created

        ports = []
        quotas = neutron.show_quota(tenant_id=context.project_id)['quota']
        if quotas.get('port', -1) == -1:
            # Unlimited Port Quota
            return num_instances
        else:
            free_ports = quotas.get('port') - len(ports)
            ports_needed = ports_needed_per_instance * num_instances
            if free_ports >= ports_needed:
                return num_instances
            else:
                return free_ports // ports_needed_per_instance
