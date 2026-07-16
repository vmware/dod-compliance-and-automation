control 'PHTN-50-000236' do
  title 'The Photon operating system must disable systemd fallback DNS.'
  desc  'Systemd contains an ability to set fallback DNS servers which is used for DNS lookups in the event no system level DNS servers are configured or other DNS servers are specified in the Systemd resolved.conf file. If uncommented this configuration contains Google DNS servers by default and could result in DNS leaking info unknowingly in the event DNS is absent or misconfigured at the system level.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify systemd fallback DNS is disabled:

    # resolvectl status | grep '^Fallback DNS'

    If the output indicates that Fallback DNS servers are configured, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/systemd/resolved.conf

    Add or update the \"FallbackDNS\" entry to the following:

    FallbackDNS=

    Restart the Systemd resolved service by running the following command:

    # systemctl restart systemd-resolved

    Note: If this option is not given, a compiled-in list of DNS servers is used instead which is undesirable.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000236'
  tag rid: 'SV-PHTN-50-000236'
  tag stig_id: 'PHTN-50-000236'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command("resolvectl status | grep 'Fallback DNS'") do
    its('stdout') { should cmp '' }
    its('stderr') { should cmp '' }
  end
end
