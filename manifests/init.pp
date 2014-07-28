############################################################
# Class: pam
#
# Description:
#  Dynamically set pam and other password options
#
# Variables:
#  None
#
# Facts:
#  None
#
# Files:
#  None
#
# Templates:
#  None
#
# Dependencies:
#  None
############################################################
class pam {
  #RHEL-06-000039, RHEL-06-000040, RHEL-06-000041
  file { '/etc/passwd':
    owner => 'root',
    group => 'root',
    mode  => '0644',
  }
  #RHEL-06-000042, RHEL-06-000043, RHEL-06-000044
  file { '/etc/group':
    owner => 'root',
    group => 'root',
    mode  => '0644',
  }
  #RHEL-06-000033, RHEL-06-000034, RHEL-06-000035
  file { '/etc/shadow':
    owner => 'root',
    group => 'root',
    mode  => '0000',
  }
  #RHEL-06-000036, RHEL-06-000037, RHEL-06-000038
  file { '/etc/gshadow':
    owner => 'root',
    group => 'root',
    mode  => '0000',
  }

  #RHEL-06-000030
  augeas { 'Prevent Log In to Accounts With Empty Password':
    context => '/files/etc/pam.d',
    changes => [
      "rm system-auth/*[type = 'password'][module = 'pam_unix.so']/argument[.= 'nullok']",
      "rm system-auth/*[type = 'auth'][module = 'pam_unix.so']/argument[.= 'nullok']",
    ],
    onlyif  => "match system-auth/*[type='password'][module='pam_unix.so']/argument[.='nullok'] size == 1",
  }
  #RHEL-06-000050, RHEL-06-000051, RHEL-06-000053, RHEL-06-000054
  augeas { 'Set Password Minimimum Length, Minimum Age, Maximum Age, and Warning Age':
    context => '/files/etc/login.defs',
    lens    => 'login_defs.lns',
    incl    => '/etc/login.defs',
    changes => [
      'set PASS_MAX_DAYS 60',
      'set PASS_MIN_DAYS 1',
      'set PASS_MIN_LEN 14',
      'set PASS_WARN_AGE 7',
    ],
  }
  #RHEL-06-000334, RHEL-06-000335
  augeas { 'Set Account Expiration Following Inactivity':
    context => '/files/etc/default/useradd',
    lens    => 'shellvars.lns',
    incl    => '/etc/default/useradd',
    changes => 'set INACTIVE 35',
  }
  #RHEL-06-000056, RHEL-06-000057, RHEL-06-000058, RHEL-06-000059, RHEL-06-000060, RHEL-06-000299
  augeas { 'Set Password Quality Requirements, if using pam_cracklib':
    context => '/files/etc/pam.d',
    changes => [
      "set system-auth/*[type='password'][module='pam_cracklib.so']/control required",
      "rm system-auth/*[type='password'][module='pam_cracklib.so']/argument",
      "set system-auth/*[type='password'][module='pam_cracklib.so']/argument[1] try_first_pass",
      "set system-auth/*[type='password'][module='pam_cracklib.so']/argument[2] retry=3",
      "set system-auth/*[type='password'][module='pam_cracklib.so']/argument[3] minlen=14",
      "set system-auth/*[type='password'][module='pam_cracklib.so']/argument[4] maxrepeat=3",
      "set system-auth/*[type='password'][module='pam_cracklib.so']/argument[5] dcredit=-1",
      "set system-auth/*[type='password'][module='pam_cracklib.so']/argument[6] ucredit=-1",
      "set system-auth/*[type='password'][module='pam_cracklib.so']/argument[7] ocredit=-1",
      "set system-auth/*[type='password'][module='pam_cracklib.so']/argument[8] lcredit=-1",
      "set system-auth/*[type='password'][module='pam_cracklib.so']/argument[9] difok=4",
    ],
    onlyif  => "match system-auth/*[type='password'][control='required'][module='pam_cracklib.so'] size == 0",
  }
  #RHEL-06-000061, RHEL-06-000356, RHEL-06-000357
  augeas { 'Set Deny For Failed Password Attempts':
    # Available faillock guidance doesn't neatly drop into place on all systems
    context => '/files/etc/pam.d',
    changes => [
      "ins 01 after system-auth/*[type='auth'][module='pam_unix.so']",
      'set system-auth/01/type auth',
      'set system-auth/01/control required',
      'set system-auth/01/module pam_faillock.so',
      'set system-auth/01/argument[1] authfail',
      'set system-auth/01/argument[2] deny=3',
      'set system-auth/01/argument[3] unlock_time=604800',
      'set system-auth/01/argument[4] fail_interval=900',
    ],
    onlyif  => "match system-auth/*[type='auth'][control='required'][module='pam_faillock.so'] size == 0",
  }
  augeas { 'Set Deny For Failed Password Attempts die':
    # Available faillock guidance doesn't neatly drop into place on all systems
    context => '/files/etc/pam.d',
    changes => [
      "ins 01 after system-auth/*[type='auth'][module='pam_unix.so']",
      'set system-auth/01/type auth',
      'set system-auth/01/control [default=die]',
      'set system-auth/01/module pam_faillock.so',
      'set system-auth/01/argument[1] authfail',
      'set system-auth/01/argument[2] deny=3',
      'set system-auth/01/argument[3] unlock_time=604800',
      'set system-auth/01/argument[4] fail_interval=900',
    ],
    onlyif  => "match system-auth/*[type='auth'][control='[default=die]'][module='pam_faillock.so'] size == 0",
  }
  #RHEL-06-000274
  augeas { 'Limit Password Reuse':
      context => '/files/etc/pam.d',
      changes => "set system-auth/*[type = 'password'][module = 'pam_unix.so']/argument[.=~regexp('remember.*')] remember=24",
      onlyif  => "match system-auth/*[type='password'][module='pam_unix.so']/argument[.='remember=24'] size == 0",
  }
  #RHEL-06-000062
  augeas { 'Set Password Hashing Algorithm in /etc/pam.d/system-auth':
    context => '/files/etc/pam.d',
    changes => [
      "set system-auth/*[type = 'password'][module = 'pam_unix.so']/argument[.=~regexp('sha512')] sha512",
      "rm system-auth/*[type = 'password'][module = 'pam_unix.so']/argument[.= 'md5']",
    ],
    onlyif  => "match system-auth/*[type='password'][module='pam_unix.so']/argument[.='sha512'] size == 0",
  }
  #RHEL-06-000063
  augeas { 'Set Password Hashing Algorithm in /etc/login.defs':
    context => '/files/etc/login.defs',
    lens    => 'login_defs.lns',
    incl    => '/etc/login.defs',
    changes => 'set ENCRYPT_METHOD SHA512',
  }

  #RHEL-06-000064
  ini_setting { 'crypt_style':
    ensure  => 'present',
    path    => '/etc/libuser.conf',
    section => 'defaults',
    setting => 'crypt_style',
    value   => 'sha512',
  }
}
