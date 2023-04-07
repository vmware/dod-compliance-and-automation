control 'VRAA-8X-000125' do
  title 'vRA must implement NIST FIPS-validated cryptography.'
  desc  'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. vRA must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc  'rationale', ''
  desc  'check', "
    Verify vRA has been installed with FIPS enabled by running the following command:

    # vracli security fips

    Example output:

    FIPS mode: strict

    If FIPS mode is not enabled, this is a finding.
  "
  desc  'fix', "
    The only way to enable FIPS mode for vRA is by configuring the setting during the installation.

    Re-deploy a new vRA appliance into the environment with FIPS mode enabled.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-VRAA-8X-000125'
  tag rid: 'SV-VRAA-8X-000125'
  tag stig_id: 'VRAA-8X-000125'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command('vracli security fips') do
    its('stdout.strip') { should cmp 'FIPS mode: strict' }
  end
end
