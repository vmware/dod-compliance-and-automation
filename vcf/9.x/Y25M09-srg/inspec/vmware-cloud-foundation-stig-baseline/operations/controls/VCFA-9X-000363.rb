control 'VCFA-9X-000363' do
  title 'VMware Cloud Foundation must be configured to forward VCF Operations logs to a central log server.'
  desc  "
    Information stored in only one location is vulnerable to accidental or incidental deletion or alteration.

    Offloading is a common process in information systems with limited audit storage capacity.
  "
  desc  'rationale', ''
  desc  'check', "
    From VCF Operations, go to Operate >> Administration >> Configurations >> Log Collection.

    Expand the \"VCF Operations\" section. For each VCF Operations instance listed select it and click Edit from the menu on the left to view the current log collection configuration.

    If log collection is not set to \"Activate\" or all logs are not configured to be forwarded, this is a finding.
  "
  desc 'fix', "
    In VCF, log collection and analysis is provided by VCF Log Management.

    From VCF Operations, go to Operate >> Administration >> Configurations >> Log Collection.

    Expand the \"VCF Operations\" section. For each VCF Operations instance listed select it and click Edit from the menu on the left.

    Ensure \"VCF Operations Log Collection\" is set to \"Activate\".

    Ensure \"Log Level\" is set to \"info\".

    For each Log entry, ensure the \"Collect\" option is enabled.

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358'
  tag satisfies: ['SRG-APP-000800']
  tag gid: 'V-VCFA-9X-000363'
  tag rid: 'SV-VCFA-9X-000363'
  tag stig_id: 'VCFA-9X-000363'
  tag cci: ['CCI-001851', 'CCI-003834']
  tag nist: ['AU-12 (3)', 'AU-4 (1)']

  describe 'This check is either manual due to no available API or is policy based and must be reviewed manually.' do
    skip 'This check is either manual due to no available API or is policy based and must be reviewed manually.'
  end
end
