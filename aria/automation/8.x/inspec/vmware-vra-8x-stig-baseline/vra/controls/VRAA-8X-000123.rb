control 'VRAA-8X-000123' do
  title 'vRA must disable the Customer Experience Improvement Program (CEIP).'
  desc  'The VMware CEIP sends VMware anonymized system information that is used to improve the quality, reliability, and functionality of VMware products and services. For confidentiality purposes, this feature must be disabled.'
  desc  'rationale', ''
  desc  'check', "
    Verify CEIP is disabled by running the following command:

    # vracli ceip status

    Example output:

    CEIP is disabled.

    If CEIP is enabled, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command:

    # vracli ceip off

    Note: The vRA services must be restarted for the command to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-VRAA-8X-000123'
  tag rid: 'SV-VRAA-8X-000123'
  tag stig_id: 'VRAA-8X-000123'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command('vracli ceip status') do
    its('stdout.strip') { should cmp 'CEIP is disabled.' }
  end
end
