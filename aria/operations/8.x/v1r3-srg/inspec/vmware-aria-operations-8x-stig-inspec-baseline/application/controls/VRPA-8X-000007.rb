control 'VRPA-8X-000007' do
  title 'VMware Aria Operations must compare internal application server clocks at least every 24 hours with an authoritative time source.'
  desc  "
    Determining the correct time a particular application event occurred on a system is critical when conducting forensic analysis and investigating system events.

    Synchronization of system clocks is needed in order to correctly correlate the timing of events that occur across multiple systems. To meet this requirement, the organization will define an authoritative time source and have each system compare its internal clock at least every 24 hours.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the vRealize Operations Manager admin portal (/admin/) as an administrator.

    In the upper right corner, click the globe icon.

    If there are not two approved authoritative time sources configured, this is a finding.
  "
  desc 'fix', "
    Login to the vRealize Operations Manager admin portal (/admin/) as an administrator.

    In the upper right corner, click the globe icon.

    Remove any unauthorized time sources and configure two authorized time sources and click ok.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000371-AS-000077'
  tag gid: 'V-VRPA-8X-000007'
  tag rid: 'SV-VRPA-8X-000007'
  tag stig_id: 'VRPA-8X-000007'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
