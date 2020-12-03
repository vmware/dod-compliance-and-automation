control 'V-219163' do
  title "The Ubuntu operating system must be configured such that Pluggable Authentication
    Module (PAM) prohibits the use of cached authentications after one day."
  desc  "If cached authentication information is out-of-date, the validity of the
    authentication information may be questionable.
  "

  impact 0.3
  tag "gtitle": "SRG-OS-000383-GPOS-00166"
  tag "gid": 'V-219163'
  tag "rid": "SV-219163r379936_rule"
  tag "stig_id": "UBTU-18-010030"
  tag "fix_id": "F-20887r304818_fix"
  tag "cci": [ "CCI-002007" ]
  tag "nist": nil
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc 'check', "If smart card authentication is not being used on the system this
    item is Not Applicable.

    Verify that Pluggable Authentication Module (PAM) prohibits the use of cached
    authentications after one day.

    Check that PAM prohibits the use of cached authentications after one day
    with the following command:

    # sudo grep offline_credentials_expiration /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf

    offline_credentials_expiration = 1

    If \"offline_credentials_expiration\" is not set to a value of \"1\", in
    /etc/sssd/sssd.conf or in a file with a name ending in .conf in the /etc/sssd/conf.d/
    directory, this is a finding.
  "
  desc 'fix', "Configure Pluggable Authentication Module (PAM) to prohibit the use of cached
    authentications after one day. Add or change the following line in \"/etc/sssd/sssd.conf\"
    just below the line \"[pam]\".

    offline_credentials_expiration = 1

    Note: It is valid for this configuration to be in a file with a name that ends with
    \".conf\" and does not begin with a \".\" in the /etc/sssd/conf.d/ directory instead of
    the /etc/sssd/sssd.conf file.
  "

  describe 'Not Applicable' do
    skip '"If smart card authentication is not being used on the system this item is Not Applicable."'
  end
end
