# -*- coding: utf-8 -*-
'''
Manage Local Policy on Windows

A policy must be setup in the 'policy_info' class to be configurable.

:depends:   - pywin32 Python module
'''

# Import python libs
from __future__ import absolute_import
import os
import logging

# Import salt libs
import salt.utils
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError
import salt.utils.dictupdate as dictupdate
from salt.ext.six import string_types
from salt.ext.six.moves import range  # pylint: disable=redefined-builtin

try:
    import win32net
    import win32security
    import uuid
    import codecs
    HAS_WINDOWS_MODULES = True
except ImportError:
    HAS_WINDOWS_MODULES = False

log = logging.getLogger(__name__)
__virtualname__ = 'gpedit'


class policy_info(object):
    '''
    policy helper stuff
    '''
    def __init__(self):
        self.policies = {
            'RestrictAnonymous': {
                'Policy': 'Network Access: Do not allow anonymous enumeration of SAM accounts and shares',
                'Settings': [0, 1],
                'How': {'Registry':
                    {'Hive': 'HKEY_LOCAL_MACHINE',
                    'Path': 'SYSTEM\\CurrentControlSet\\Control\\Lsa',
                    'Value': 'RestrictAnonymous',
                    'Type': 'REG_DWORD'
                    },
                },
                'Transform': {
                    'Get': '_enable1_disable0_conversion',
                    'Put': '_enable1_disable0_reverse_conversion',
                },
            },
            'PasswordHistory': {
                'Policy': 'Enforce password history',
                'Settings': {
                    'Function': '_in_range_inclusive',
                    'Args': {'min': 0, 'max': 24}
                },
                'How': {'NetUserModal':
                    {'Modal': 0,
                    'Option': 'password_hist_len'
                    }
                },
            },
            'MaxPasswordAge': {
                'Policy': 'Maximum password age',
                'Settings': {
                    'Function': '_in_range_inclusive',
                    'Args': {'min': 0, 'max': 86313600}
                },
                'How': {'NetUserModal':
                    {'Modal': 0,
                    'Option': 'max_passwd_age',
                    }
                },
                'Transform': {
                    'Get': '_seconds_to_days',
                    'Put': '_days_to_seconds'
                },
            },
            'MinPasswordAge': {
                'Policy': 'Minimum password age',
                'Settings': {
                    'Function': '_in_range_inclusive',
                    'Args': {'min': 0, 'max': 86313600}
                },
                'How': {'NetUserModal':
                    {'Modal': 0,
                    'Option': 'min_passwd_age',
                    }
                },
                'Transform': {
                    'Get': '_seconds_to_days',
                    'Put': '_days_to_seconds'
                },
            },
            'MinPasswordLen': {
                'Policy': 'Minimum password length',
                'Settings': {
                    'Function': '_in_range_inclusive',
                    'Args': {'min': 0, 'max': 14}
                },
                'How': {'NetUserModal':
                    {'Modal': 0,
                    'Option': 'min_passwd_len',
                    }
                },
            },
            'PasswordComplexity': {
                'Policy': 'Passwords must meet complexity requirements',
                'Settings': [0, 1],
                'How': {'Secedit':
                    {'Option':'PasswordComplexity',
                    'Section': 'System Access',
                    }
                },
                'Transform': {
                    'Get': '_enable1_disable0_conversion',
                    'Put': '_enable1_disable0_reverse_conversion',
                },
            },
            'ClearTextPasswords': {
                'Policy': 'Store passwords using reversible encryption',
                'Settings': [0, 1],
                'How': {'Secedit':
                    {'Option':'ClearTextPassword',
                    'Section': 'System Access',
                    }
                },
                'Transform': {
                    'Get': '_enable1_disable0_conversion',
                    'Put': '_enable1_disable0_reverse_conversion',
                },
            },
            'AdminAccountStatus': {
                'Policy': 'Accounts: Administrator account status',
                'Settings': [0, 1],
                'How': {'Secedit':
                    {'Option':'EnableAdminAccount',
                    'Section': 'System Access',
                    }
                },
                'Transform': {
                    'Get': '_enable1_disable0_conversion',
                    'Put': '_enable1_disable0_reverse_conversion',
                },
            },
            'GuestAccountStatus': {
                'Policy': 'Accounts: Guest account status',
                'Settings': [0, 1],
                'How': {'Secedit':
                    {'Option':'EnableGuestAccount',
                    'Section': 'System Access',
                    }
                },
                'Transform': {
                    'Get': '_enable1_disable0_conversion',
                    'Put': '_enable1_disable0_reverse_conversion',
                },
            },
            'LimitBlankPasswordUse': {
                'Policy': 'Accounts: Limit local account use of blank passwords to console logon only',
                'Settings': [0, 1],
                'How': {'Registry':
                    {'Hive': 'HKEY_LOCAL_MACHINE',
                    'Path': 'SYSTEM\\CurrentControlSet\\Control\\Lsa',
                    'Value': 'limitblankpassworduse',
                    'Type': 'REG_DWORD',
                    },
                },
                'Transform': {
                    'Get': '_enable1_disable0_conversion',
                    'Put': '_enable1_disable0_reverse_conversion',
                },
            },
            'RenameAdministratorAccount': {
                'Policy': 'Accounts: Rename administrator account',
                'Settings': None,
                'How': {'Secedit':
                    {'Option':'NewAdministratorName',
                    'Section': 'System Access',
                    }
                },
                'Transform': {
                    'Get': '_strip_quotes',
                    'Put': '_add_quotes',
                },
            },
            'RenameGuestAccount': {
                'Policy': 'Accounts: Rename guest account',
                'Settings': None,
                'How': {'Secedit':
                    {'Option':'NewGuestName',
                    'Section': 'System Access',
                    }
                },
                'Transform': {
                    'Get': '_strip_quotes',
                    'Put': '_add_quotes',
                },
            },
            'AuditBaseObjects': {
                'Policy': 'Audit: Audit the access of global system objects',
                'Settings': [0, 1],
                'How': {'Registry':
                    {'Hive': 'HKEY_LOCAL_MACHINE',
                    'Path': 'SYSTEM\\CurrentControlSet\\Control\\Lsa',
                    'Value': 'AuditBaseObjects',
                    'Type': 'REG_DWORD',
                    }
                },
                'Transform': {
                    'Get': '_enable1_disable0_conversion',
                    'Put': '_enable1_disable0_reverse_conversion',
                },
            },
            'FullPrivilegeAuditing': {
                'Policy': 'Audit: Audit the use of Backup and Restore privilege',
                'Settings': [chr(0), chr(1)],
                'How': {'Registry':
                    {'Hive': 'HKEY_LOCAL_MACHINE',
                    'Path': 'System\\CurrentControlSet\\Control\\Lsa',
                    'Value': 'FullPrivilegeAuditing',
                    'Type': 'REG_BINARY',
                    }
                },
                'Transform': {
                    'Get': '_binary_enable0_disable1_conversion',
                    'Put': '_binary_enable0_disable1_reverse_conversion',
                },
            },
            'CrashOnAuditFail': {
                'Policy': 'Audit: Shut down system immediately if unable to log security audits',
                'Settings': [0, 1],
                'How': {'Registry':
                    {'Hive': 'HKEY_LOCAL_MACHINE',
                    'Path': 'SYSTEM\\CurrentControlSet\\Control\\Lsa',
                    'Value': 'CrashOnAuditFail',
                    'Type': 'REG_DWORD',
                    }
                },
                'Transform': {
                    'Get': '_enable1_disable0_conversion',
                    'Put': '_enable1_disable0_reverse_conversion',
                },
            },
            #'DcomAccessRestrictions': {
            #    'Policy': 'DCOM: Machine Access Restrictions in Security Descriptor Definition Language (SDDL) Syntax'
            #},
            #'DcomLaunchRestrictions': {
            #    'Policy': 'DCOM: Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) Syntax'
            #},
            'UndockWithoutLogon': {
                'Policy': 'Devices: Allow undock without having to log on',
                'Settings': [0, 1],
                'How': {'Registry':
                    {'Hive': 'HKEY_LOCAL_MACHINE',
                    'Path': 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
                    'Value': 'UndockWithoutLogon',
                    'Type': 'REG_DWORD',
                    }
                },
                'Transform': {
                    'Get': '_enable1_disable0_conversion',
                    'Put': '_enable1_disable0_reverse_conversion',
                },
            },
            'AllocateDASD': {
                'Policy': 'Devices: Allowed to format and eject removable media',
                'Settings': ["", "0", "1", "2"],
                'How': {'Registry':
                    {'Hive': 'HKEY_LOCAL_MACHINE',
                    'Path': 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
                    'Value': 'AllocateDASD',
                    'Type': 'REG_SZ',
                    }
                },
                'Transform': {
                    'Get': '_dasd_conversion',
                    'Put': '_dasd_reverse_conversion',
                },
            },
            'AllocateCDRoms': {
                'Policy': 'Devices: Restrict CD-ROM access to locally logged-on user only',
                'Settings': ["0", "1"],
                'How': {'Registry':
                    {'Hive': 'HKEY_LOCAL_MACHINE',
                    'Path': 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
                    'Value': 'AllocateCDRoms',
                    'Type': 'REG_SZ',
                    }
                },
                'Transform': {
                    'Get': '_enable1_disable0_conversion',
                    'Put': '_enable1_disable0_reverse_conversion',
                    'PutArgs': {'return_string': True}
                },
            },
            'AllocateFloppies': {
                'Policy': 'Devices: Restrict floppy access to locally logged-on user only',
                'Settings': ["0", "1"],
                'How': {'Registry':
                    {'Hive': 'HKEY_LOCAL_MACHINE',
                    'Path': 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
                    'Value': 'AllocateFloppies',
                    'Type': 'REG_SZ',
                    }
                },
                'Transform': {
                    'Get': '_enable1_disable0_conversion',
                    'Put': '_enable1_disable0_reverse_conversion',
                    'PutArgs': {'return_string': True}
                },
            },
            #see KB298503 why we aren't just doing this one via the registry
            'DriverSigningPolicy': {
                'Policy': 'Devices: Unsigned driver installation behavior',
                'Settings': ['3,0', '3,' + chr(1), '3,' + chr(2)],
                'How': {'Secedit':
                    {'Option': 'MACHINE\Software\Microsoft\Driver Signing\Policy',
                    'Section': 'Registry Values',
                    }
                },
                'Transform': {
                    'Get': '_driver_signing_reg_conversion',
                    'Put': '_driver_signing_reg_reverse_conversion',
                },
            },
            'LockoutDuration': {
                'Policy': 'Account lockout duration',
                'Settings': {
                    'Function': '_in_range_inclusive',
                    'Args': {'min': 0, 'max': 6000000}
                },
                'How': {'NetUserModal':
                    {'Modal': 3,
                    'Option': 'lockout_duration',
                    }
                },
                'Transform': {
                    'Get': '_seconds_to_minutes',
                    'Put': '_minutes_to_seconds',
                },
            },
            'LockoutThreshold': {
                'Policy': 'Account lockout threshold',
                'Settings': {
                    'Function': '_in_range_inclusive',
                    'Args': {'min': 0, 'max': 1000}
                },
                'How': {'NetUserModal':
                    {'Modal': 3,
                    'Option': 'lockout_threshold',
                    }
                }
            },
            'LockoutWindow': {
                'Policy': 'Reset account lockout counter after',
                'Settings': {
                    'Function': '_in_range_inclusive',
                    'Args': {'min': 0, 'max': 6000000}
                },
                #'True if {0} >= 0 and {0} <= 6000000 else False',
                'How': {'NetUserModal':
                    {'Modal': 3,
                    'Option': 'lockout_observation_window',
                    },
                },
                'Transform': {
                    'Get': '_seconds_to_minutes',
                    'Put': '_minutes_to_seconds'
                },
            },
            'AuditLogonEvents': {
                'Policy': 'Audit account logon events',
                'Settings': [0, 1, 2, 3],
                'How': {'Secedit':
                    {'Option': 'AuditLogonEvents',
                    'Section': 'Event Audit',
                    }
                },
                'Transform': {
                    'Get': '_event_audit_conversion',
                    'Put': '_event_audit_reverse_conversion',
                },
            },
            'AuditAccountManage': {
                'Policy': 'Audit account management',
                'Settings': [0, 1, 2, 3],
                'How': {'Secedit':
                    {'Option': 'AuditAccountManage',
                    'Section': 'Event Audit',
                    }
                },
                'Transform': {
                    'Get': '_event_audit_conversion',
                    'Put': '_event_audit_reverse_conversion',
                },
            },
            'AuditDSAccess': {
                'Policy': 'Audit directory service access',
                'Settings': [0, 1, 2, 3],
                'How': {'Secedit':
                    {'Option': 'AuditDSAccess',
                    'Section': 'Event Audit',
                    }
                },
                'Transform': {
                    'Get': '_event_audit_conversion',
                    'Put': '_event_audit_reverse_conversion',
                },
            },
            'AuditLogonEvents': {
                'Policy': 'Audit logon events',
                'Settings': [0, 1, 2, 3],
                'How': {'Secedit':
                    {'Option': 'AuditLogonEvents',
                    'Section': 'Event Audit',
                    }
                },
                'Transform': {
                    'Get': '_event_audit_conversion',
                    'Put': '_event_audit_reverse_conversion',
                },
            },
            'AuditObjectAccess': {
                'Policy': 'Audit object access',
                'Settings': [0, 1, 2, 3],
                'How': {'Secedit':
                    {'Option': 'AuditObjectAccess',
                    'Section': 'Event Audit',
                    }
                },
                'Transform': {
                    'Get': '_event_audit_conversion',
                    'Put': '_event_audit_reverse_conversion',
                },
            },
            'AuditPolicyChange': {
                'Policy': 'Audit policy change',
                'Settings': [0, 1, 2, 3],
                'How': {'Secedit':
                    {'Option':'AuditPolicyChange',
                    'Section': 'Event Audit',
                    }
                },
                'Transform': {
                    'Get': '_event_audit_conversion',
                    'Put': '_event_audit_reverse_conversion',
                },
            },
            'AuditPrivilegeUse': {
                'Policy': 'Audit privilege use',
                'Settings': [0, 1, 2, 3],
                'How': {'Secedit':
                    {'Option':'AuditPrivilegeUse',
                    'Section': 'Event Audit',
                    }
                },
                'Transform': {
                    'Get': '_event_audit_conversion',
                    'Put': '_event_audit_reverse_conversion',
                },
            },
            'AuditProcessTracking': {
                'Policy': 'Audit process tracking',
                'Settings': [0, 1, 2, 3],
                'How': {'Secedit':
                    {'Option':'AuditProcessTracking',
                    'Section': 'Event Audit',
                    }
                },
                'Transform': {
                    'Get': '_event_audit_conversion',
                    'Put': '_event_audit_reverse_conversion',
                },
            },
            'AuditSystemEvents': {
                'Policy': 'Audit system events',
                'Settings': [0, 1, 2, 3],
                'How': {'Secedit':
                    {'Option':'AuditSystemEvents',
                    'Section': 'Event Audit',
                    }
                },
                'Transform': {
                    'Get': '_event_audit_conversion',
                    'Put': '_event_audit_reverse_conversion',
                },
            },
            'SeNetworkLogonRight': {
                'Policy': 'Access this computer from the network',
                'Settings': None,
                'How': {'LsaRights':
                    {'Option': 'SeNetworkLogonRight'}
                },
                'Transform': {
                    'Get': '_sidConversion',
                    'Put': '_usernamesToSidObjects',
                },
            },
            'SeTcbPrivilege': {
                'Policy': 'Act as part of the operating system',
                'Settings': None,
                'How': {'LsaRights':
                    {'Option': 'SeTcbPrivilege'}
                },
                'Transform': {
                    'Get': '_sidConversion',
                    'Put': '_usernamesToSidObjects',
                },
            },
            'SeMachineAccountPrivilege': {
                'Policy': 'Add workstations to domain',
                'Settings': None,
                'How': {'LsaRights':
                    {'Option': 'SeMachineAccountPrivilege'}
                },
                'Transform': {
                    'Get': '_sidConversion',
                    'Put': '_usernamesToSidObjects',
                },
            },
            'SeIncreaseQuotaPrivilege': {
                'Policy': 'Adjust memory quotas for a process',
                'Settings': None,
                'How': {'LsaRights':
                    {'Option': 'SeIncreaseQuotaPrivilege'}
                },
                'Transform': {
                    'Get': '_sidConversion',
                    'Put': '_usernamesToSidObjects',
                },
            },
            'SeInteractiveLogonRight': {
                'Policy': 'Allow logon locally',
                'Settings': None,
                'How': {'LsaRights':
                    {'Option': 'SeInteractiveLogonRight'}
                },
                'Transform': {
                    'Get': '_sidConversion',
                    'Put': '_usernamesToSidObjects',
                },
            },
            'SeRemoteInteractiveLogonRight': {
                'Policy': 'Allow logon through Remote Desktop Services',
                'Settings': None,
                'How': {'LsaRights':
                    {'Option': 'SeRemoteInteractiveLogonRight'}
                },
                'Transform': {
                    'Get': '_sidConversion',
                    'Put': '_usernamesToSidObjects',
                },
            },
        }


    def _enable1_disable0_conversion(self, val, **kwargs):
        '''
        converts a reg dword 1/0 value to the strings enable/disable
        '''
        if val != None:
            if val == 1 or val == "1":
                return 'Enabled'
            elif val == 0 or val == "0":
                return 'Disabled'
            else:
                return 'Invalid Value'
        else:
            return 'Not Defined'


    def _enable1_disable0_reverse_conversion(self, val, **kwargs):
        '''
        converts Enable/Disable to 1/0
        '''
        return_string = False
        if kwargs.has_key('return_string'):
            return_string = True
        if val != None:
            if val.upper() == 'ENABLED':
                if return_string:
                    return '1'
                else:
                    return 1
            elif val.upper() == 'DISABLED':
                if return_string:
                    return '0'
                else:
                    return 0
            else:
                return 'Invalid Value'
        else:
            return 'Not Defined'


    def _event_audit_conversion(self, val, **kwargs):
        '''
        converts an audit setting # (0, 1, 2, 3) to the string text
        '''
        if val != None:
            if val == 0 or val == "0":
                return 'No auditing'
            elif val == 1 or val == "1":
                return 'Success'
            elif val == 2 or val == "2":
                return 'Failure'
            elif val == 3 or val == "3":
                return 'Succes, Failure'
            else:
                return 'Invalid Auditing Value'
        else:
            return 'Not Defined'


    def _event_audit_reverse_conversion(self, val, **kwargs):
        '''
        converts audit strings to numerical values
        '''
        if val != None:
            if val.upper() == 'NO AUDITING':
                return 0
            elif val.upper() == 'SUCCESS':
                return 1
            elif val.upper() == 'FAILURE':
                return 2
            elif val.upper() == 'SUCCESS, FAILURE':
                return 3
        else:
            return 'Not Defined'


    def _seconds_to_days(self, val, **kwargs):
        '''
        converts a number of seconds to days
        '''
        if val != None:
            return val / 86400
        else:
            return 'Not Defined'


    def _days_to_seconds(self, val, **kwargs):
        '''
        converts a number of days to seconds
        '''
        if val != None:
            return val * 86400
        else:
            return 'Not Defined'


    def _seconds_to_minutes(self, val, **kwargs):
        '''
        converts a number of seconds to minutes
        '''
        if val != None:
            return val / 60
        else:
            return 'Not Defined'


    def _minutes_to_seconds(self, val, **kwargs):
        '''
        converts number of minutes to seconds
        '''
        if val != None:
            return val * 60
        else:
            return 'Not Defined'


    def _strip_quotes(self, val, **kwargs):
        '''
        strips quotes from a string
        '''
        return val.replace('"', '')


    def _add_quotes(self, val, **kwargs):
        '''
        add quotes around the string
        '''
        return '"{0}"'.format(val)


    def _binary_enable0_disable1_conversion(self, val, **kwargs):
        '''
        converts a binary 0/1 to Disabled/Enabled
        '''
        if val != None:
            if ord(val) == 0:
                return 'Disabled'
            elif ord(val) == 1:
                return 'Enabled'
            else:
                return 'Invalid Value'
        else:
            return 'Not Defined'


    def _binary_enable0_disable1_reverse_conversion(self, val, **kwargs):
        '''
        converts Enabled/Disabled to unicode char to write to a REG_BINARY value
        '''
        if val != None:
            if val.upper() == 'DISABLED':
                return chr(0)
            elif val.upper() == 'ENABLED':
                return chr(1)
            else:
                return 'Invalid Value'
        else:
            return 'Not Defined'


    def _dasd_conversion(self, val, **kwargs):
        '''
        converts 0/1/2 for dasd reg key
        '''
        if val != None:
            if val == '0' or val == 0 or val == '':
                return 'Administrtors'
            elif val == '1' or val == 1:
                return 'Administrators and Power Users'
            elif val == '2' or val == 2:
                return 'Administrators and Interactive Users'
            else:
                return 'Not Defined'
        else:
            return 'Not Defined'


    def _dasd_reverse_conversion(self, val, **kwargs):
        '''
        converts DASD String values to the reg_sz value
        '''
        if val != None:
            if val.upper() == 'ADMINISTRATORS':
                #"" also shows 'administrators' in the gui
                return '0'
            elif val.upper() == 'ADMINISTRATORS AND POWER USERS':
                return '1'
            elif val.upper() == 'ADMINISTRATORS AND INTERACTIVE USERS':
                return '2'
            elif val.upper() == 'NOT DEFINED':
                #a setting of anything other than nothing,0,1,2 or if they doesn't exist shows 'not defined'
                return '9999'
            else:
                return 'Invalid Value'
        else:
            return 'Not Defined'


    def _in_range_inclusive(self, val, **kwargs):
        '''
        checks that a value is in an inclusive range
        '''
        min = 0
        max = 1
        if kwargs.has_key('min'):
            min = kwargs['min']
        if kwargs.has_key('max'):
            max = kwargs['max']

        if val != None:
            if val >= min and val <= max:
                return True
            else:
                return False
        else:
            return False


    def _driver_signing_reg_conversion(self, val, **kwargs):
        '''
        converts the binary value in the registry for driver signing into the correct string representation
        '''
        log.debug('we have {0} for the driver signing value'.format(val))
        if val != None:
            #since this is from secedit, it should be 3,<value>
            _val = val.split(',')
            if len(_val) == 2:
                if _val[1] == '0':
                    return 'Silently Succeed'
                elif _val[1] == '1':
                    return 'Warn but allow installation'
                elif _val[1] == '2':
                    return 'Do not allow installation'
                elif _val[1] == 'Not Defined':
                    return 'Not Defined'
                else:
                    return 'Invalid Value'
            else:
                return 'Not Defined'
        else:
            return 'Not Defined'


    def _driver_signing_reg_reverse_conversion(self, val, **kwargs):
        '''
        converts the string value seen in the gui to the correct registry value for seceit
        '''
        if val != None:
            if val.upper() == 'SILENTLY SUCCEED':
                return ','.join(['3', '0'])
            elif val.upper() == 'WARN BUT ALLOW INSTALLATION':
                return ','.join(['3', chr(1)])
            elif val.upper() == 'DO NOT ALLOW INSTALLATION':
                return ','.join(['3', chr(2)])
            else:
                return 'Invalid Value'
        else:
            return 'Not Defined'


    def _sidConversion(self, val, **kwargs):
        '''
        converts a list of pysid objects to string representations
        '''
        sids = []
        for _sid in val:
            try:
                userSid = win32security.LookupAccountSid('', _sid)
                if userSid[1]:
                    userSid = '{1}\\{0}'.format(userSid[0], userSid[1])
                else:
                    userSid = '{0}'.format(userSid[0])
            except Exception:
                userSid = win32security.ConvertSidToStringSid(_sid)
            sids.append(userSid)
        return sids

def __virtual__():
    '''
    Only works on Windows systems
    '''
    if salt.utils.is_windows() and HAS_WINDOWS_MODULES:
        return __virtualname__
    return False


def _findOptionValueInSeceditFile(option):
    '''
    helper function to dump/parse a `secedit /export` file for a particular option
    '''
    try:
        _d = uuid.uuid4().hex
        _tfile = '{0}\\{1}'.format(__salt__['config.get']('cachedir'), 'salt-secedit-dump-{0}.txt'.format(_d))
        _ret = __salt__['cmd.run']('secedit /export /cfg {0}'.format(_tfile))
        if _ret:
            _reader = codecs.open(_tfile, 'r', encoding='utf-16')
            _secdata = _reader.readlines()
            _reader.close()
            _ret = __salt__['file.remove'](_tfile)
            for _line in _secdata:
                if _line.startswith(option):
                    return True, _line.split('=')[1].strip()
        return True, 'Not Defined'
    except:
        log.debug('error occurred while trying to get secedit data')
        return False, None


def _importSeceditConfig(infData):
    '''
    helper function to write data to a temp file/run secedit to import policy/cleanup
    '''
    try:
        _d = uuid.uuid4().hex
        _tSdbfile = '{0}\\{1}'.format(__salt__['config.get']('cachedir'), 'salt-secedit-import-{0}.sdb'.format(_d))
        _tInfFile = '{0}\\{1}'.format(__salt__['config.get']('cachedir'), 'salt-secedit-config-{0}.inf'.format(_d))
        #make sure our temp files don't already exist
        _ret = __salt__['file.remove'](_tSdbfile)
        _ret = __salt__['file.remove'](_tInfFile)
        #add the inf data to the file, win_file sure could use the write() function
        _ret = __salt__['file.touch'](_tInfFile)
        _ret = __salt__['file.append'](_tInfFile, infData)
        #run secedit to make the change
        _ret = __salt__['cmd.run']('secedit /configure /db {0} /cfg {1}'.format(_tSdbfile, _tInfFile))
        #cleanup our temp files
        _ret = __salt__['file.remove'](_tSdbfile)
        _ret = __salt__['file.remove'](_tInfFile)
        return True
    except:
        log.debug('error occurred while trying to import secedit data')
        return False


def _transformValue(value, policy, transformType):
    '''
    helper function to transform the policy value into something that more closely matches how the policy is displayed in the gpedit gui
    '''
    t_kwargs = {}
    if policy.has_key('Transform'):
        if policy['Transform'].has_key(transformType):
            _policydata = policy_info()
            if policy['Transform'].has_key(transformType + 'Args'):
                t_kwargs = policy['Transform'][transformType + 'Args']
            return getattr(_policydata, policy['Transform'][transformType])(value, **t_kwargs)
        else:
            return value
    else:
        return value


def _validateSetting(value, policy):
    '''
    helper function to validate specified value is appropriate for the policy
    if the 'Settings' key is a list, the value will checked that it is in the list
    if the 'Settings' key is a dict
        we will try to execute the function name from the 'Function' key, passing the value and additional arguments from the 'Args' dict
    if the 'Settings' key is None, we won't do any validation and just return True
    '''
    if policy.has_key('Settings'):
        if policy['Settings']:
            if isinstance(policy['Settings'], list):
                if value in policy['Settings']:
                    return True
                else:
                    return False
            elif isinstance(policy['Settings'], dict):
                _policydata = policy_info()
                return getattr(_policydata, policy['Settings']['Function'])(value, **policy['Settings']['Args'])
        else:
            return True
    else:
        return True


def _addAccountRights():
    h = win32security.LsaOpenPolicy(None, win32security.POLICY_ALL_ACCESS)
    #get all the SIDs that have a certain right
    _sids = win32security.LsaEnumerateAccountsWithUserRight(h, userRight)
    _ret = win32security.LsaAddAccountRights(h, sidObject, userRightsList)
    _ret = win32security.LsaRemoveAccountRights(h, sidObject, False, userRightsList)


def _getRightsAssignments(userRight):
    '''
    helper function to return all the user rights assignments/users
    '''
    sids = []
    _polHandle = win32security.LsaOpenPolicy(None, win32security.POLICY_ALL_ACCESS)
    _sids = win32security.LsaEnumerateAccountsWithUserRight(_polHandle, userRight)
    return _sids
    


def get(policy_names=None, return_full_policy_names=False):
    '''
    Get a policy value

    :param list policy_names:
        A list of policy_names to display the values of.  A string of policy names will be split on commas

    :param boolean return_full_policy_names:
        True/False to return the policy name as it is seen in the gpedit.msc GUI

    :rtype: dict

    CLI Example:

    .. code-block:: bash

        salt '*' gpedit.get return_full_policy_names=True

        salt '*' gpedit.get RestrictAnonymous,LockoutDuration
    '''

    vals = {}
    modal_returns = {}
    _policydata = policy_info()

    if policy_names:
        if isinstance(policy_names, string_types):
            policy_names = policy_names.split(',')
    else:
        policy_names = _policydata.policies.keys()

    for policy_name in policy_names:
        _pol = None
        if _policydata.policies.has_key(policy_name):
            _pol = _policydata.policies[policy_name]
        else:
            for p in _policydata.policies.keys():
                if _policydata.policies[p]['Policy'].upper() == policy_name.upper():
                    _pol = _policydata.policies[p]
                    policy_name = p
        if _pol:
            if _pol['How'].has_key('Registry'):
                #get value from registry
                #TODO: needs to be updated for the 2015.5+ read_value/dict return
                vals[policy_name] = __salt__['reg.read_key'](_pol['How']['Registry']['Hive'], _pol['How']['Registry']['Path'], _pol['How']['Registry']['Value'])
                log.debug('Value {0} found for reg policy {1}'.format(vals[policy_name], policy_name))
            elif _pol['How'].has_key('Secedit'):
                #get value from secedit
                _ret, _val = _findOptionValueInSeceditFile(_pol['How']['Secedit']['Option'])
                if _ret:
                    vals[policy_name] = _val
                else:
                    msg = 'An error occurred attempting to get the value of policy {0} from secedit.'.format(policy_name)
                    raise CommandExecutionError(msg)
            elif _pol['How'].has_key('NetUserModal'):
                #get value from UserNetMod
                if not modal_returns.has_key(_pol['How']['NetUserModal']['Modal']):
                    modal_returns[_pol['How']['NetUserModal']['Modal']] = win32net.NetUserModalsGet(None, _pol['How']['NetUserModal']['Modal'])
                vals[policy_name] = vals[policy_name] = modal_returns[_pol['How']['NetUserModal']['Modal']][_pol['How']['NetUserModal']['Option']]
            elif _pol['How'].has_key('LsaRights'):
                vals[policy_name] = _getRightsAssignments(_pol['How']['LsaRights']['Option'])
            if vals.has_key(policy_name):
                vals[policy_name] = _transformValue(vals[policy_name], _policydata.policies[policy_name], 'Get')
            if return_full_policy_names:
                vals[_policydata.policies[policy_name]['Policy']] = vals.pop(policy_name)
        else:
            msg = 'The specified policy {0} is not currently available to be configured via this module'.format(policy_name)
            raise SaltInvocationError(msg)
    return vals


def set(**kwargs):
    '''
    Set a local server policy

    :param str kwargs:
        policyname=value kwargs for all the policies you want to set
        the 'value' should be how it is displayed in the gpedit gui, i.e. if a setting can be 'Enabled'/'Disabled', then that should be passed

    :rtype: boolean

    CLI Example:

    .. code-block:: bash

        salt '*' gpedit.set LockoutDuration=2 RestrictAnonymous=Enabled AuditProcessTracking='Succes, Failure'
    '''

    if kwargs:
        _secedits = {}
        _modal_sets = {}
        
        _policydata = policy_info()
        log.debug('KWARGS keys = {0}'.format(kwargs.keys()))
        for policy_name in kwargs.keys():
            if not policy_name.startswith('__pub_'):
                _pol = None
                if _policydata.policies.has_key(policy_name):
                    _pol = _policydata.policies[policy_name]
                else:
                    for p in _policydata.policies.keys():
                        if _policydata.policies[p]['Policy'].upper().replace(' ', '_') == policy_name.upper():
                            _pol = _policydata.policies[p]
                            policy_name = p
                if _pol:
                    #transform and validate the setting
                    _value = _transformValue(kwargs[policy_name], _policydata.policies[policy_name], 'Put')
                    if not _validateSetting(_value, _policydata.policies[policy_name]):
                        msg = 'The specified value {0} is not an acceptable setting for policy {1}.'.format(kwargs[policy_name], policy_name)
                        raise SaltInvocationError(msg)
                    if _pol['How'].has_key('Registry'):
                        #set value in registry
                        log.debug('{0} is a Registry policy'.format(policy_name))
                        _ret = __salt__['reg.set_key'](_pol['How']['Registry']['Hive'], _pol['How']['Registry']['Path'], _pol['How']['Registry']['Value'], _value, _pol['How']['Registry']['Type'])
                        if not _ret:
                            msg = 'Error while attempting to set policy {0} via the registry.  Some changes may not be applied as expected.'.format(policy_name)
                            raise CommandExecutionError(msg)
                    elif _pol['How'].has_key('Secedit'):
                        #set value with secedit
                        log.debug('{0} is a Secedit policy'.format(policy_name))
                        if not _secedits.has_key(_pol['How']['Secedit']['Section']):
                            _secedits[_pol['How']['Secedit']['Section']] = []
                        _secedits[_pol['How']['Secedit']['Section']].append(' '.join([_pol['How']['Secedit']['Option'], '=', str(_value)]))
                    elif _pol['How'].has_key('NetUserModal'):
                        #set value via NetUserModal
                        log.debug('{0} is a NetUserModal policy'.format(policy_name))
                        if not _modal_sets.has_key(_pol['How']['NetUserModal']['Modal']):
                            _modal_sets[_pol['How']['NetUserModal']['Modal']] = {}
                        _modal_sets[_pol['How']['NetUserModal']['Modal']][_pol['How']['NetUserModal']['Option']] = _value
                else:
                    msg = 'The specified policy {0} is not currently available to be configured via this module'.format(policy_name)
                    raise SaltInvocationError(msg)
        if _secedits:
            #we've got secedits to make
            log.debug(_secedits)
            _iniData = '\r\n'.join(['[Unicode]','Unicode=yes'])
            _seceditSections = ['System Access', 'Event Audit', 'Registry Values', 'Privilege Rights']
            for _seceditSection in _seceditSections:
                if _secedits.has_key(_seceditSection):
                    _iniData = '\r\n'.join([_iniData, ''.join(['[', _seceditSection, ']']), '\r\n'.join(_secedits[_seceditSection])])
            _iniData = '\r\n'.join([_iniData, '[Version]', 'signature="$CHICAGO$"', 'Revision=1'])
            log.debug('_iniData == {0}'.format(_iniData))
            _ret = _importSeceditConfig(_iniData)
            if not _ret:
                msg = 'Error while attempting to set policies via secedit.  Some changes may not be applied as expected.'
                raise CommandExecutionError(msg)
        if _modal_sets:
            #we've got modalsets to make
            log.debug(_modal_sets)
            for _modal_set in _modal_sets.keys():
                try:
                    _existingModalData = win32net.NetUserModalsGet(None, _modal_set)
                    _newModalSetData = dictupdate.update(_existingModalData, _modal_sets[_modal_set])
                    log.debug('NEW MODAL SET = {0}'.format(_newModalSetData))
                    _ret = win32net.NetUserModalsSet(None, _modal_set, _newModalSetData)
                except:
                    msg = 'An unhandled exception occurred while attempting to set policy via NetUserModalSet'
                    raise CommandExecutionError(msg)
        return True
    else:
        msg = 'You have to specify something!'
        raise SaltInvocationError(msg)