control 'UBTU-22-631015' do
  title 'Ubuntu 22.04 LTS must be configured such that Pluggable Authentication Module (PAM) prohibits the use of cached authentications after one day.'
  desc 'If cached authentication information is out-of-date, the validity of the authentication information may be questionable.'
  desc 'check', %q(Verify that PAM prohibits the use of cached authentications after one day by using the following command:

Note: If smart card authentication is not being used on the system, this requirement is not applicable.

     $ sudo grep -i '^\s*offline_credentials_expiration' /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf
     /etc/sssd/sssd.conf:offline_credentials_expiration = 1

If "offline_credentials_expiration" is not set to "1", is commented out, is missing, or conflicting results are returned, this is a finding.)
  desc 'fix', 'Configure PAM to prohibit the use of cached authentications after one day.

Add or modify the following line in the "/etc/sssd/sssd.conf" file, just below the line "[pam]":

offline_credentials_expiration = 1

Note: It is valid for this configuration to be in a file with a name that ends with ".conf" and does not begin with a "." in the "/etc/sssd/conf.d/" directory instead of the "/etc/sssd/sssd.conf" file.'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64310r953554_chk'
  tag severity: 'low'
  tag gid: 'V-260581'
  tag rid: 'SV-260581r958828_rule'
  tag stig_id: 'UBTU-22-631015'
  tag gtitle: 'SRG-OS-000383-GPOS-00166'
  tag fix_id: 'F-64218r953555_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']

  sssd_conf_path = input('sssd_conf_path')
  smartcards_used = input('smartcards_used')

  if smartcards_used
    if sssd_conf_path.exist?
      describe parse_config_file(sssd_conf_path) do
        its('offline_credentials_expiration') { should cmp '1' }
      end
    else
      describe file(sssd_conf_path) do
        it { should exist }
      end
    end
  else
    impact 0.0
    describe 'Smartcards not in use for local login so this rule is N/A.' do
      skip 'Smartcards not in use for local login so this rule is N/A.'
    end
  end
end
