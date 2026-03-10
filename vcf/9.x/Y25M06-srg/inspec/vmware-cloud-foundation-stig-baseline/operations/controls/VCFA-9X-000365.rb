control 'VCFA-9X-000365' do
  title 'VMware Cloud Foundation must be configured to forward VCF Operations Fleet Management logs to a central log server.'
  desc  "
    Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

    Offloading is a common process in information systems with limited audit storage capacity.
  "
  desc  'rationale', ''
  desc  'check', "
    From VCF Operations, go to Fleet Management >> Lifecycle >> VCF Management >> Settings >> Logs.

    Review the \"Operations for Logs Agent Configuration\" section and verify it is configured to forward logs.

    If log forwarding is not enabled, this is a finding.
  "
  desc 'fix', "
    In VCF, log collection and analysis is provided by VCF Operations for Logs. By default, the VCF Fleet Management appliance has the VCF Operations for Logs agent already installed.

    From VCF Operations, go to Fleet Management >> Lifecycle >> VCF Management >> Settings >> Logs.

    Under \"Operations for Logs Agent Configuration\" configure the hostname for the VCF Operations for Logs instance in the environment.

    For port, enter either 9000 or 9543 for SSL connections.

    Select \"CFAPI\" for the protocol.

    Optionally select SSL and configure the SSL trust settings.

    Click Save to complete the configuration.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358'
  tag gid: 'V-VCFA-9X-000365'
  tag rid: 'SV-VCFA-9X-000365'
  tag stig_id: 'VCFA-9X-000365'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  describe 'This check is either manual due to no available API or is policy based and must be reviewed manually.' do
    skip 'This check is either manual due to no available API or is policy based and must be reviewed manually.'
  end
end
