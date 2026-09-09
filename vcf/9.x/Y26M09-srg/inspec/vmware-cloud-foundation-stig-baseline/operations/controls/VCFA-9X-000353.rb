control 'VCFA-9X-000353' do
  title 'VMware Cloud Foundation Operations must enable firewall hardening.'
  desc  'In a VCF Operations cluster there are some network ports which are used only for inter-node communication, however these ports accept incoming connections from any source. In order to secure these ports the firewall hardening option should be enabled which restricts access to these ports to only members of the Operations cluster.'
  desc  'rationale', ''
  desc  'check', "
    Login to the admin portal (/admin/) as an administrator.

    Go to Administrator Settings >> Security Settings.

    View the status of \"Firewall Hardening\".

    If \"Firewall Hardening\" is not activated, this is a finding.
  "
  desc 'fix', "
    Enabling firewall hardening must be done from the admin portal. Login to the admin portal (/admin/) as an administrator.

    Go to Administrator Settings >> Security Settings.

    Click the \"Activate Firewall Hardening\" button.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCFA-9X-000353'
  tag rid: 'SV-VCFA-9X-000353'
  tag stig_id: 'VCFA-9X-000353'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is either manual due to no available API or is policy based and must be reviewed manually.' do
    skip 'This check is either manual due to no available API or is policy based and must be reviewed manually.'
  end
end
