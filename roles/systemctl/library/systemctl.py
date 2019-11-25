#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2016, Brian Coca <bcoca@ansible.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['demo'],
                    'supported_by': 'TAM'}

DOCUMENTATION = '''
module: systemctl
author:
    - Red Hat TAM
version_added: "2.2"
short_description:  Manage services
description:
    - Controls systemd services on remote hosts.
options:
    name:
        description:
            - Name of the service. When using in a chroot environment you always need to specify the full name i.e. (crond.service).
        aliases: [ service, unit ]
    properties:
        description:
            - Run ``systemctl set-property`` for each name/value pair provided.
            - The property name must already exist in the output of ``systemctl show``
        type: dict
        version_added: "2.10"
requirements:
    - A system managed by systemd.
'''

EXAMPLES = '''
- name: set CPUShares and MemoryLimit on sshd.service
  systemctl:
    name: sshd.service
    properties:
      CPUShares: 750
      MemoryLimit: "750M"

- name: set CPUShares to the default value on sshd.service
  systemctl:
    name: sshd.service
    properties:
      CPUShares: ""
'''

RETURN = '''
status:
    description: A dictionary with the key=value pairs returned from `systemctl show`
    returned: success
    type: complex
    contains: {
            "ActiveEnterTimestamp": "Sun 2016-05-15 18:28:49 EDT",
            "ActiveEnterTimestampMonotonic": "8135942",
            "ActiveExitTimestampMonotonic": "0",
            "ActiveState": "active",
            "After": "auditd.service systemd-user-sessions.service time-sync.target systemd-journald.socket basic.target system.slice",
            "AllowIsolate": "no",
            "Before": "shutdown.target multi-user.target",
            "BlockIOAccounting": "no",
            "BlockIOWeight": "1000",
            "CPUAccounting": "no",
            "CPUSchedulingPolicy": "0",
            "CPUSchedulingPriority": "0",
            "CPUSchedulingResetOnFork": "no",
            "CPUShares": "1024",
            "CanIsolate": "no",
            "CanReload": "yes",
            "CanStart": "yes",
            "CanStop": "yes",
            "CapabilityBoundingSet": "18446744073709551615",
            "ConditionResult": "yes",
            "ConditionTimestamp": "Sun 2016-05-15 18:28:49 EDT",
            "ConditionTimestampMonotonic": "7902742",
            "Conflicts": "shutdown.target",
            "ControlGroup": "/system.slice/crond.service",
            "ControlPID": "0",
            "DefaultDependencies": "yes",
            "Delegate": "no",
            "Description": "Command Scheduler",
            "DevicePolicy": "auto",
            "EnvironmentFile": "/etc/sysconfig/crond (ignore_errors=no)",
            "ExecMainCode": "0",
            "ExecMainExitTimestampMonotonic": "0",
            "ExecMainPID": "595",
            "ExecMainStartTimestamp": "Sun 2016-05-15 18:28:49 EDT",
            "ExecMainStartTimestampMonotonic": "8134990",
            "ExecMainStatus": "0",
            "ExecReload": "{ path=/bin/kill ; argv[]=/bin/kill -HUP $MAINPID ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
            "ExecStart": "{ path=/usr/sbin/crond ; argv[]=/usr/sbin/crond -n $CRONDARGS ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
            "FragmentPath": "/usr/lib/systemd/system/crond.service",
            "GuessMainPID": "yes",
            "IOScheduling": "0",
            "Id": "crond.service",
            "IgnoreOnIsolate": "no",
            "IgnoreOnSnapshot": "no",
            "IgnoreSIGPIPE": "yes",
            "InactiveEnterTimestampMonotonic": "0",
            "InactiveExitTimestamp": "Sun 2016-05-15 18:28:49 EDT",
            "InactiveExitTimestampMonotonic": "8135942",
            "JobTimeoutUSec": "0",
            "KillMode": "process",
            "KillSignal": "15",
            "LimitAS": "18446744073709551615",
            "LimitCORE": "18446744073709551615",
            "LimitCPU": "18446744073709551615",
            "LimitDATA": "18446744073709551615",
            "LimitFSIZE": "18446744073709551615",
            "LimitLOCKS": "18446744073709551615",
            "LimitMEMLOCK": "65536",
            "LimitMSGQUEUE": "819200",
            "LimitNICE": "0",
            "LimitNOFILE": "4096",
            "LimitNPROC": "3902",
            "LimitRSS": "18446744073709551615",
            "LimitRTPRIO": "0",
            "LimitRTTIME": "18446744073709551615",
            "LimitSIGPENDING": "3902",
            "LimitSTACK": "18446744073709551615",
            "LoadState": "loaded",
            "MainPID": "595",
            "MemoryAccounting": "no",
            "MemoryLimit": "18446744073709551615",
            "MountFlags": "0",
            "Names": "crond.service",
            "NeedDaemonReload": "no",
            "Nice": "0",
            "NoNewPrivileges": "no",
            "NonBlocking": "no",
            "NotifyAccess": "none",
            "OOMScoreAdjust": "0",
            "OnFailureIsolate": "no",
            "PermissionsStartOnly": "no",
            "PrivateNetwork": "no",
            "PrivateTmp": "no",
            "RefuseManualStart": "no",
            "RefuseManualStop": "no",
            "RemainAfterExit": "no",
            "Requires": "basic.target",
            "Restart": "no",
            "RestartUSec": "100ms",
            "Result": "success",
            "RootDirectoryStartOnly": "no",
            "SameProcessGroup": "no",
            "SecureBits": "0",
            "SendSIGHUP": "no",
            "SendSIGKILL": "yes",
            "Slice": "system.slice",
            "StandardError": "inherit",
            "StandardInput": "null",
            "StandardOutput": "journal",
            "StartLimitAction": "none",
            "StartLimitBurst": "5",
            "StartLimitInterval": "10000000",
            "StatusErrno": "0",
            "StopWhenUnneeded": "no",
            "SubState": "running",
            "SyslogLevelPrefix": "yes",
            "SyslogPriority": "30",
            "TTYReset": "no",
            "TTYVHangup": "no",
            "TTYVTDisallocate": "no",
            "TimeoutStartUSec": "1min 30s",
            "TimeoutStopUSec": "1min 30s",
            "TimerSlackNSec": "50000",
            "Transient": "no",
            "Type": "simple",
            "UMask": "0022",
            "UnitFileState": "enabled",
            "WantedBy": "multi-user.target",
            "Wants": "system.slice",
            "WatchdogTimestampMonotonic": "0",
            "WatchdogUSec": "0",
        }
'''  # NOQA

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.service import sysv_exists, sysv_is_enabled, fail_if_missing
from ansible.module_utils._text import to_native


def is_running_service(service_status):
    return service_status['ActiveState'] in set(['active', 'activating'])


def request_was_ignored(out):
    return '=' not in out and 'ignoring request' in out


def parse_systemctl_show(lines):
    # The output of 'systemctl show' can contain values that span multiple lines. At first glance it
    # appears that such values are always surrounded by {}, so the previous version of this code
    # assumed that any value starting with { was a multi-line value; it would then consume lines
    # until it saw a line that ended with }. However, it is possible to have a single-line value
    # that starts with { but does not end with } (this could happen in the value for Description=,
    # for example), and the previous version of this code would then consume all remaining lines as
    # part of that value. Cryptically, this would lead to Ansible reporting that the service file
    # couldn't be found.
    #
    # To avoid this issue, the following code only accepts multi-line values for keys whose names
    # start with Exec (e.g., ExecStart=), since these are the only keys whose values are known to
    # span multiple lines.
    parsed = {}
    multival = []
    k = None
    for line in lines:
        if k is None:
            if '=' in line:
                k, v = line.split('=', 1)
                if k.startswith('Exec') and v.lstrip().startswith('{'):
                    if not v.rstrip().endswith('}'):
                        multival.append(v)
                        continue
                parsed[k] = v.strip()
                k = None
        else:
            multival.append(line)
            if line.rstrip().endswith('}'):
                parsed[k] = '\n'.join(multival).strip()
                multival = []
                k = None
    return parsed

def convert_property_suffix(raw_value):
    import math

    # check if we have an int, in which case there is nothing to convert
    if isinstance(raw_value, int) or raw_value == "":
        return raw_value

    last_char = raw_value[-1]
    size_converter = {"K": 1, "M": 2, "G": 3, "T": 4}

    if last_char.upper() in size_converter:
        p = int(math.pow(1024, size_converter[last_char.upper()]))
        sz = int(raw_value[:-1]) * p
        return sz
    else:
        return raw_value

# ===========================================
# Main control flow

def main():
    # initialize
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='str', aliases=['service', 'unit']),
            properties=dict(type='dict'),
        ),
        supports_check_mode=True,
        required_one_of=[['properties']],
    )

    systemctl = module.get_bin_path('systemctl', True)

    unit = module.params['name']
    rc = 0
    out = err = ''
    result = dict(
        name=unit,
        changed=False,
        status=dict(),
    )

    for requires in ('properties'):
        if module.params[requires] is not None and unit is None:
            module.fail_json(msg="name is also required when specifying %s" % requires)

    if unit:
        found = False
        is_initd = sysv_exists(unit)
        is_systemd = False

        # check service data, cannot error out on rc as it changes across versions, assume not found
        (rc, out, err) = module.run_command("%s show '%s'" % (systemctl, unit))

        if request_was_ignored(out) or request_was_ignored(err):
            # fallback list-unit-files as show does not work on some systems (chroot)
            # not used as primary as it skips some services (like those using init.d) and requires .service/etc notation
            (rc, out, err) = module.run_command("%s list-unit-files '%s'" % (systemctl, unit))
            if rc == 0:
                is_systemd = True

        elif rc == 0:
            # load return of systemctl show into dictionary for easy access and return
            if out:
                result['status'] = parse_systemctl_show(to_native(out).split('\n'))

                is_systemd = 'LoadState' in result['status'] and result['status']['LoadState'] != 'not-found'

                is_masked = 'LoadState' in result['status'] and result['status']['LoadState'] == 'masked'

                # Check for loading error
                if is_systemd and not is_masked and 'LoadError' in result['status']:
                    module.fail_json(msg="Error loading unit file '%s': %s" % (unit, result['status']['LoadError']))
        else:
            # Check for systemctl command
            module.run_command(systemctl, check_rc=True)

        # Does service exist?
        found = is_systemd or is_initd
        if is_initd and not is_systemd:
            module.warn('The service (%s) is actually an init script but the system is managed by systemd' % unit)

        # set service properties if requested and this is not an initd service.  Should be done before starting the service.
        if module.params['properties'] is not None and not is_initd:
            fail_if_missing(module, found, unit, msg="host")

            # loop through all of the properties we want to set
            prop_list = module.params['properties']
            prop_action = ""
            for prop in prop_list.keys():
                # convert the output to a str as that is what result['status'][prop] will be when we compare later
                prop_val = str(convert_property_suffix(prop_list[prop]))

                # the property name must already be in the output from `systemctl show`
                if prop in result['status'] and prop_val != result['status'][prop]:
                    prop_action += (" %s=%s" % (prop, prop_val))

            # Modify all items
            if prop_action and not module.check_mode:
                result['changed'] = True
                (rc, out, err) = module.run_command("%s set-property %s %s" % (systemctl, unit, prop_action))
                if rc != 0:
                    module.fail_json(msg="Unable to set-property service %s - %s: %s" % (unit, prop_action, err))
                else:
                    # In the case where we have updated properties we need to pull the full list again
                    # so that the result[status] reflects the new values
                    (rc, out, err) = module.run_command("%s show '%s'" % (systemctl, unit))

                    if rc == 0:
                        # load return of systemctl show into dictionary for easy access and return
                        if out:
                            result['status'] = parse_systemctl_show(to_native(out).split('\n'))

    module.exit_json(**result)


if __name__ == '__main__':
    main()
