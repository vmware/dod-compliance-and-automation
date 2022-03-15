control 'PHTN-67-000066' do
  title "The Photon operating system must prohibit the use of cached
authenticators after one day."
  desc  "If cached authentication information is out of date, the validity of
the authentication information may be questionable."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # /opt/likewise/bin/lwregshell list_values
\"HKEY_THIS_MACHINE\\Services\\lsass\\Parameters\\Providers\\ActiveDirectory\"|grep
\"CacheEntryExpiry\"

    If the value returned is not 14400 or less, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following command:

    # /opt/likewise/bin/lwregshell set_value
\"[HKEY_THIS_MACHINE\\Services\\lsass\\Parameters\\Providers\\ActiveDirectory]\"
CacheEntryExpiry 14400
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000383-GPOS-00166'
  tag gid: 'V-239137'
  tag rid: 'SV-239137r675219_rule'
  tag stig_id: 'PHTN-67-000066'
  tag fix_id: 'F-42307r675218_fix'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']

  describe command('/opt/likewise/bin/lwregshell list_values "HKEY_THIS_MACHINE\Services\lsass\Parameters\Providers\ActiveDirectory"|grep "CacheEntryExpiry"') do
    its('stdout') { should match /^(?=.*?\bCacheEntryExpiry\b)(?=.*?\bREG_DWORD\b)(?=.*?\b14400\b).*$/ }
  end
end
