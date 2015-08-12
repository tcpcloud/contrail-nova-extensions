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
from oslo.config import cfg

from nova.api.openstack import extensions
from nova.compute import flavors
from nova.compute import utils as compute_utils
from nova import conductor
from nova import exception
from nova.i18n import _, _LE, _LW
from nova.network import base_api
from nova.network import model as network_model
from nova.network import neutronv2
from nova.network.neutronv2.api import API as neutronv2_api
from nova.network.neutronv2 import constants
from nova import objects
from nova.openstack.common import excutils
from nova.openstack.common import lockutils
from nova.openstack.common.gettextutils import _
from nova.openstack.common import log as logging
from nova.openstack.common import uuidutils
from nova.pci import pci_manager
from nova.pci import pci_request
from nova.pci import pci_whitelist

CONF = cfg.CONF
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

        if requested_networks is None or len(requested_networks) == 0:
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
            instance_on_net_ids = []
            net_ids_requested = []

            # TODO(danms): Remove me when all callers pass an object
            if isinstance(requested_networks[0], tuple):
                requested_networks = objects.NetworkRequestList(
                    objects=[objects.NetworkRequest.from_tuple(t)
                             for t in requested_networks])

            for request in requested_networks:
                if request.port_id:
                    try:
                        port = neutron.show_port(request.port_id).get('port')
                    except neutron_client_exc.NeutronClientException as e:
                        if e.status_code == 404:
                            port = None
                        else:
                            with excutils.save_and_reraise_exception():
                                LOG.exception(_LE("Failed to access port %s"),
                                              request.port_id)
                    if not port:
                        raise exception.PortNotFound(port_id=request.port_id)
                    if port.get('device_id', None):
                        raise exception.PortInUse(port_id=request.port_id)
                    if not port.get('fixed_ips'):
                        raise exception.PortRequiresFixedIP(
                            port_id=request.port_id)
                    request.network_id = port['network_id']
                else:
                    ports_needed_per_instance += 1
                    net_ids_requested.append(request.network_id)

                    # NOTE(jecarey) There is currently a race condition.
                    # That is, if you have more than one request for a specific
                    # fixed IP at the same time then only one will be allocated
                    # the ip. The fixed IP will be allocated to only one of the
                    # instances that will run. The second instance will fail on
                    # spawn. That instance will go into error state.
                    # TODO(jecarey) Need to address this race condition once we
                    # have the ability to update mac addresses in Neutron.
                    if request.address:
                        # TODO(jecarey) Need to look at consolidating list_port
                        # calls once able to OR filters.
                        search_opts = {'network_id': request.network_id,
                                       'fixed_ips': 'ip_address=%s' % (
                                           request.address),
                                       'fields': 'device_id'}
                        existing_ports = neutron.list_ports(
                                                    **search_opts)['ports']
                        if existing_ports:
                            i_uuid = existing_ports[0]['device_id']
                            raise exception.FixedIpAlreadyInUse(
                                                    address=request.address,
                                                    instance_uuid=i_uuid)

                if (not CONF.neutron.allow_duplicate_networks and
                    request.network_id in instance_on_net_ids):
                        raise exception.NetworkDuplicated(
                            network_id=request.network_id)
                instance_on_net_ids.append(request.network_id)

            # Now check to see if all requested networks exist
            if net_ids_requested:
                nets = self._get_available_networks(
                    context, context.project_id, net_ids_requested,
                    neutron=neutron)

                for net in nets:
                    if not net.get('subnets'):
                        raise exception.NetworkRequiresSubnet(
                            network_uuid=net['id'])

                if len(nets) != len(net_ids_requested):
                    requested_netid_set = set(net_ids_requested)
                    returned_netid_set = set([net['id'] for net in nets])
                    lostid_set = requested_netid_set - returned_netid_set
                    if lostid_set:
                        id_str = ''
                        for _id in lostid_set:
                            id_str = id_str and id_str + ', ' + _id or _id
                        raise exception.NetworkNotFound(network_id=id_str)

        # Note(PhilD): Ideally Nova would create all required ports as part of
        # network validation, but port creation requires some details
        # from the hypervisor.  So we just check the quota and return
        # how many of the requested number of instances can be created
        if ports_needed_per_instance:
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
        return num_instances
