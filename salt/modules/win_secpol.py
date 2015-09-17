# -*- coding: utf-8 -*-
'''
Manage Security Policy on Windows
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
from salt.ext.six import string_types
from salt.ext.six.moves import range  # pylint: disable=redefined-builtin

try:
    import win32net
    import uuid
    import codecs
    HAS_WINDOWS_MODULES = True
except ImportError:
    HAS_WINDOWS_MODULES = False

log = logging.getLogger(__name__)
__virtualname__ = 'win_secpol'


class policy_info(object):
    '''
    policy helper stuff
    '''
    def __init__(self):
        self.policies = {
            'RestrictAnonymous': {
                'Policy': 'Network Access: Do not allow anonymous enumeration of SAM accounts and shares',
                'Settings': {'Enabled':1, 'Disabled':0},
                'How': {'Registry':
                    {'Hive': 'HKEY_LOCAL_MACHINE',
                    'Path': '\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
                    'Value': 'RestrictAnonymous'
                    },
                },
                'Transform': {
                    'Get': '"Enabled" if {0} == 1 else "Disabled"',
                    'Put': '1 if "{0}".upper() == "Enabled".upper() else 0',
                },
            },
            'PasswordHistory': {
                'Policy': 'Enforce password history',
                'Settings': range(25),
                'How': {'NetUserModal':
                    {'Modal': 0,
                    'Option': 'password_hist_len'
                    }
                },
            },
            'MaxPasswordAge': {
                'Policy': 'Maximum password age',
                'Settings': range(1000),
                'How': {'NetUserModal':
                    {'Modal': 0,
                    'Option': 'max_passwd_age',
                    }
                },
                'Transform': {
                    'Get': '{0} / 86400',
                    'Put': '{0} * 86400'
                },
            },
            'MinPasswordAge': {
                'Policy': 'Minimum password age',
                'Settings': range(999),
                'How': {'NetUserModal':
                    {'Modal': 0,
                    'Option': 'min_passwd_age',
                    }
                },
                'Transform': {
                    'Get': '{0} / 86400',
                    'Put': '{0} * 86400'
                },
            },
            'MinPasswordLen': {
                'Policy': 'Minimum password length',
                'Settings': range(15),
                'How': {'NetUserModal':
                    {'Modal': 0,
                    'Option': 'min_passwd_len',
                    }
                },
            },
            'PasswordComplexity': {
                'Policy': 'Passwords must meet complexity requirements',
                'Settings': {'Enabled':1, 'Disabled':0},
                'How': {'Secedit':
                    {'Option':'PasswordComplexity',
                    'Section': 'System Access',
                    }
                },
                'Transform': {
                    'Get': '"Enabled" if {0} == 1 else "Disabled"',
                    'Put': '1 if "{0}".upper() == "Enabled".upper() else 0',
                },
            },
            'ClearTextPasswords': {
                'Policy': 'Store passwords using reversible encryption',
                'Settings': {'Enabled':1, 'Disabled':0},
                'How': {'Secedit':
                    {'Option':'ClearTextPassword',
                    'Section': 'System Access',
                    }
                },
                'Transform': {
                    'Get': '"Enabled" if {0} == 1 else "Disabled"',
                    'Put': '1 if "{0}".upper() == "Enabled".upper() else 0',
                },
            },
            'AdminAccountStatus': {
                'Policy': 'Accounts: Administrator account status',
                'Settings': {'Enabled':1, 'Disabled':0},
                'How': {'Secedit':
                    {'Option':'EnableAdminAccount',
                    'Section': 'System Access',
                    }
                },
                'Transform': {
                    'Get': '"Enabled" if {0} == 1 else "Disabled"',
                    'Put': '1 if "{0}".upper() == "Enabled".upper() else 0',
                },
            },
            'GuestAccountStatus': {
                'Policy': 'Accounts: Guest account status',
                'Settings': {'Enabled':1, 'Disabled':0},
                'How': {'Secedit':
                    {'Option':'EnableGuestAccount',
                    'Section': 'System Access',
                    }
                },
                'Transform': {
                    'Get': '"Enabled" if {0} == 1 else "Disabled"',
                    'Put': '1 if "{0}".upper() == "Enabled".upper() else 0',
                },
            },
            'BlankPasswordUse': {
                'Policy': 'Accounts: Limit local account use of blank passwords to console logon only',
                'Settings': {'Enabled':1, 'Disabled':0},
                'How': {'Registry':
                    {'Hive': 'HKEY_LOCAL_MACHINE',
                    'Path': '\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
                    'Value': 'limitblankpassworduse'
                    },
                },
                'Transform': {
                    'Get': '"Enabled" if {0} == 1 else "Disabled"',
                    'Put': '1 if "{0}".upper() == "Enabled".upper() else 0',
                },
            },
            'RenameAdministraorAccount': {
                'Policy': 'Accounts: Rename administrator account',
                'Settings': None,
                'How': {'Secedit':
                    {'Option':'NewAdministratorName',
                    'Section': 'System Access',
                    }
                },
                'Transform': {
                    'Get': '{0}.replace(\'"\',\'\')',
                    'Put': '"{0}"',
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
                    'Get': '{0}.replace(\'"\',\'\')',
                    'Put': '"{0}"',
                },
            },
            'LockoutDuration': {
                'Policy': 'Account lockout duration',
                'Settings': range(100000),
                'How': {'NetUserModal':
                    {'Modal': 3,
                    'Option': 'lockout_duration',
                    }
                },
                'Transform': {
                    'Get': '{0} / 60',
                    'Put': '{0} * 60',
                },
            },
            'LockoutThreshold': {
                'Policy': 'Account lockout threshold',
                'Settings': range(1000),
                'How': {'NetUserModal':
                    {'Modal': 3,
                    'Option': 'lockout_threshold',
                    }
                }
            },
            'LockoutWindow': {
                'Policy': 'Reset account lockout counter after',
                'Settings': range(100000),
                'How': {'NetUserModal':
                    {'Modal': 3,
                    'Option': 'lockout_observation_window',
                    },
                },
                'Transform': {
                    'Get': '{0} / 60',
                    'Put': '{0} * 60'
                },
            },
            'AuditLogonEvents': {
                'Policy': 'Audit account logon events',
                'Settings': {'Success': 1, 'Failure': 2, 'Success and Failure': 3},
                'How': {'Secedit':
                    {'Option': 'AuditLogonEvents',
                    'Section': 'Event Audit',
                    }
                },
                'Transform': {
                    'Get': '"Success" if {0} == 1 else ("Failure" if {0} == 2 else ("Success and Failure" if {0} == 3 else "No auditing"))',
                    'Put': '',
                },
            },
            'AuditAccountManage': {
                'Policy': 'Audit account management',
                'Settings': {'Success': 1, 'Failure': 2, 'Success and Failure': 3},
                'How': {'Secedit':
                    {'Option': 'AuditAccountManage',
                    'Section': 'Event Audit',
                    }
                },
                'Transform': {
                    'Get': '"Success" if {0} == 1 else ("Failure" if {0} == 2 else ("Success and Failure" if {0} == 3 else "No auditing"))',
                    'Put': '',
                },
            },
            'AuditDSAccess': {
                'Policy': 'Audit directory service access',
                'Settings': {'Success': 1, 'Failure': 2, 'Success and Failure': 3},
                'How': {'Secedit':
                    {'Option': 'AuditDSAccess',
                    'Section': 'Event Audit',
                    }
                },
                'Transform': {
                    'Get': '"Success" if {0} == 1 else ("Failure" if {0} == 2 else ("Success and Failure" if {0} == 3 else "No auditing"))',
                    'Put': '',
                },
            },
            'AuditLogonEvents': {
                'Policy': 'Audit logon events',
                'Settings': {'Success': 1, 'Failure': 2, 'Success and Failure': 3},
                'How': {'Secedit':
                    {'Option': 'AuditLogonEvents',
                    'Section': 'Event Audit',
                    }
                },
                'Transform': {
                    'Get': '"Success" if {0} == 1 else ("Failure" if {0} == 2 else ("Success and Failure" if {0} == 3 else "No auditing"))',
                    'Put': '',
                },
            },
            'AuditObjectAccess': {
                'Policy': 'Audit object access',
                'Settings': {'Success': 1, 'Failure': 2, 'Success and Failure': 3},
                'How': {'Secedit':
                    {'Option': 'AuditObjectAccess',
                    'Section': 'Event Audit',
                    }
                },
                'Transform': {
                    'Get': '"Success" if {0} == 1 else ("Failure" if {0} == 2 else ("Success and Failure" if {0} == 3 else "No auditing"))',
                    'Put': '',
                },
            },
            'AuditPolicyChange': {
                'Policy': 'Audit policy change',
                'Settings': {'Success': 1, 'Failure': 2, 'Success and Failure': 3},
                'How': {'Secedit':
                    {'Option':'AuditPolicyChange',
                    'Section': 'Event Audit',
                    }
                },
                'Transform': {
                    'Get': '"Success" if {0} == 1 else ("Failure" if {0} == 2 else ("Success and Failure" if {0} == 3 else "No auditing"))',
                    'Put': '',
                },
            },
            'AuditPrivilegeUse': {
                'Policy': 'Audit privilege use',
                'Settings': {'Success': 1, 'Failure': 2, 'Success and Failure': 3},
                'How': {'Secedit':
                    {'Option':'AuditPrivilegeUse',
                    'Section': 'Event Audit',
                    }
                },
                'Transform': {
                    'Get': '"Success" if {0} == 1 else ("Failure" if {0} == 2 else ("Success and Failure" if {0} == 3 else "No auditing"))',
                    'Put': '',
                },
            },
            'AuditProcessTracking': {
                'Policy': 'Audit process tracking',
                'Settings': {'Success': 1, 'Failure': 2, 'Success and Failure': 3},
                'How': {'Secedit':
                    {'Option':'AuditProcessTracking',
                    'Section': 'Event Audit',
                    }
                },
                'Transform': {
                    'Get': '"Success" if {0} == 1 else ("Failure" if {0} == 2 else ("Success and Failure" if {0} == 3 else "No auditing"))',
                    'Put': '',
                },
            },
            'AuditSystemEvents': {
                'Policy': 'Audit system events',
                'Settings': {'Success': 1, 'Failure': 2, 'Success and Failure': 3},
                'How': {'Secedit':
                    {'Option':'AuditSystemEvents',
                    'Section': 'Event Audit',
                    }
                },
                'Transform': {
                    'Get': '"Success" if {0} == 1 else ("Failure" if {0} == 2 else ("Success and Failure" if {0} == 3 else "No auditing"))',
                    'Put': '',
                },
            },
        }


def __virtual__():
    '''
    Only works on Windows systems
    '''
    if salt.utils.is_windows() and HAS_WINDOWS_MODULES:
        return __virtualname__
    return False


def get_password_policy():
    '''
    Gets the password policy of the local machine

    CLI Example:
    .. code-block:: bash
        salt '*' win_secpol.get_password_policy
    '''
    try:
        _vals = win32net.NetUserModalsGet(None, 0)
        #convert to days to match GP display value
        if _vals.has_key('min_passwd_age'):
            _vals['min_passwd_age'] = _vals['min_passwd_age'] / 86400
        if _vals.has_key('max_passwd_age'):
            _vals['max_passwd_age'] = _vals['max_passwd_age'] / 86400
        if _vals.has_key('force_logoff'):
            if _vals['force_logoff'] == 0:
                _vals['force_logoff'] = True
            else:
                _vals['force_logoff'] = False

        _ret, _val = _findOptionValueInSeceditFile('PasswordComplexity')
        if _ret:
            _vals['PasswordComplexity'] = bool(int(_val))
        _ret, _val = _findOptionValueInSeceditFile('ClearTextPassword')
        if _ret:
            _vals['ClearTextPassword'] = bool(int(_val))
        return _vals
    except:
        msg = 'An unhandled exception occurred!'
        raise CommandExecutionError(msg)


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
        return False, None
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


def get_lockout_policy():
    '''
    Gets the lockout policy of the local machine

    CLI Example:
    .. code-block:: bash
        salt '*' win_secpol.get_lockout_policy
    '''

    try:
        _vals = win32net.NetUserModalsGet(None, 3)
        # convert the values to minutes to mimic the GP display values
        if _vals.has_key('lockout_observation_window'):
            _vals['lockout_observation_window'] = _vals['lockout_observation_window'] / 60
        if _vals.has_key('lockout_duration'):
            _vals['lockout_duration'] = _vals['lockout_duration'] / 60
        return _vals
    except:
        msg = 'An unhandled exception occurred!'
        raise CommandExecutionError(msg)


def set_lockout_policy(lockout_duration=None, lockout_observation_window=None, lockout_threshold=None):
    '''
    Sets the account lockout policy on the local machine
    
    lockout_duration:
        The number of minutes a locked-out account remains locked out before automatically becoming unlocked

    lockout_observation_window:
        The number of minutes that must elapse after a failed logon attempt before the failed logon attempt counter is reset to 0 bad logon attempts
  
    lockout_threshold:
        The number of failed logon attempts that causes a user account to be locked out
        
    CLI Example:
    .. code-block:: bash
        salt '*' win_secpol.set_lockout_policy 1440 1440 10
    '''

    try:
        data = {}
        current_settings = get_lockout_policy()
        if current_settings:
            if lockout_duration:
                data['lockout_duration'] = lockout_duration * 60
            else:
                data['lockout_duration'] = current_settings['lockout_duration'] * 60
            if lockout_observation_window:
                data['lockout_observation_window'] = lockout_observation_window * 60
            else:
                data['lockout_observation_window'] = current_settings['lockout_observation_window'] * 60
            if lockout_threshold:
                data['lockout_threshold'] = lockout_threshold
            else:
                data['lockout_threshold'] = current_settings['lockout_threshold']
            _ret = win32net.NetUserModalsSet(None, 3, data)
            return True
        else:
            #error getting current settings
            msg = 'An error occurred while retrieving the existing lockout policy.'
            raise CommandExecutionError(msg)
    except:
        msg = 'An unhandled exception occurred!'
        raise CommandExecutionError(msg)


def set_password_policy(force_logoff=None, max_passwd_age=None, min_passwd_age=None, min_passwd_len=None, password_hist_len=None, PasswordComplexity=None, ClearTextPasswords=None):
    '''
    Sets the password policy of the local machine

    force_logoff
        force logoff when logon time expires True/False

    max_passwd_age
        The period of time (in days) that a password can be used before the system requires the user to change it

    min_passwd_age
        The period of time (in days) that a password must be used before the user can change it

    min_passwd_len
        The least number of characters that a password for a user account may contain

    password_hist_len
        The number of unique new passwords that have to be associated with a user account before an old password can be reused

    PasswordComplexity
        Enable password complexity [True/False/1/0]

    ClearTextPasswords
        Enable storing passwords with reversible encryption [True/False/1/0]
    '''

    valid_force_logoff = [0, 1, True, False]
    valid_password_complexity = [0, 1, True, False]
    valid_reverse_encryption = [0, 1, True, False]
    password_complexity_inf = '[Unicode]\r\nUnicode=yes\r\n[System Access]\r\nPasswordComplexity = {0}\r\n[Version]\r\nsignature="$CHICAGO$"\r\nRevision=1'
    password_reverse_encryption_inf = '[Unicode]\r\nUnicode=yes\r\n[System Access]\r\nClearTextPassword = {0}\r\n[Version]\r\nsignature="$CHICAGO$"\r\nRevision=1'
    try:
        data = {}
        current_settings = get_password_policy()
        if current_settings:
            if force_logoff:
                if not force_logoff in valid_force_logoff:
                    msg = 'The force_logoff setting {0} is invalid, it should be one of the following: {1}'.format(
                            force_logoff, valid_force_logoff)
                    raise SaltInvocationError(msg)
                if force_logoff == True:
                    data['force_logoff'] = 0
                else:
                    data['force_logoff'] = 4294967295
            else:
                data['force_logoff'] = current_settings['force_logoff']
            if max_passwd_age:
                data['max_passwd_age'] = max_passwd_age * 86400
            else:
                data['max_passwd_age'] = current_settings['max_passwd_age'] * 86400
            if min_passwd_age:
                data['min_passwd_age'] = min_passwd_age * 86400
            else:
                data['min_passwd_age'] = current_settings['min_passwd_age'] * 86400
            if min_passwd_len:
                data['min_passwd_len'] = min_passwd_len
            else:
                data['min_passwd_len'] = current_settings['min_passwd_len']
            if password_hist_len:
                data['password_hist_len'] = password_hist_len
            else:
                data['password_hist_len'] = current_settings['password_hist_len']

            if ClearTextPasswords:
                if not ClearTextPasswords in valid_reverse_encryption:
                    msg = 'The store_passwords_reversible_encryption setting {0} is invalid, it should be one of the following: {1}'.format(
                            ClearTextPasswords, valid_reverse_encryption)
                    raise SaltInvocationError(msg)
                else:
                    _ret = _importSeceditConfig(password_reverse_encryption_inf.format(int(ClearTextPasswords)))
                    if not _ret:
                        log.debug('error while attempting to set reversible encryption setting')
                        return False
            if PasswordComplexity:
                if not PasswordComplexity in valid_password_complexity:
                    msg = 'The require_password_complexity setting {0} is invalid, it should be one of the following: {1}'.format(
                            PasswordComplexity, valid_password_complexity)
                    raise SaltInvocationError(msg)
                else:
                    _ret = _importSeceditConfig(password_complexity_inf.format(int(PasswordComplexity)))
                    if not _ret:
                        log.debug('error while attempting to set password complexity setting')
                        return False
            _ret = win32net.NetUserModalsSet(None, 0, data)
            return True
        else:
            #error getting current settings
            msg = 'An error occurred while retrieving the existing password policy.'
            raise CommandExecutionError(msg)
    except:
        msg = 'An unhandled exception occurred!'
        raise CommandExecutionError(msg)


def _transformValue(value, policy, transformType):
    '''
    helper function to transform the policy value into something that more closely matches how the policy is displayed in the gpedit gui
    
    probably should use something other than eval
    '''
    if policy.has_key('Transform'):
        if policy['Transform'].has_key(transformType):
            return eval(policy['Transform'][transformType].format(value))
        else:
            return value
    else:
        return value


def get(policy_names=None, return_full_policy_names=False):
    '''
    Get a policy value
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
                vals[policy_name] = __salt__['reg.read_key'](_pol['How']['Registry']['Hive'], _pol['How']['Registry']['Path'], _pol['How']['Registry']['Value'])
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
            if vals.has_key(policy_name):
                vals[policy_name] = _transformValue(vals[policy_name], _policydata.policies[policy_name], 'Get')
            if return_full_policy_names:
                vals[_policydata.policies[policy_name]['Policy']] = vals.pop(policy_name)
        else:
            msg = 'The specified policy {0} is not currently available to be configured via this module'.format(policy_name)
            raise SaltInvocationError(msg)
    return vals


def set(policy_names, policy_values):
    '''
    Set a local server policy

    policy_name
        the policy name to set (see policies class)

    policy_value
        the value to set for the policy
    '''
    pass
