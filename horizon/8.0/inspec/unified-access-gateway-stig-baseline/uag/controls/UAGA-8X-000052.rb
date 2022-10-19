control 'UAGA-8X-000052' do
  title 'The UAG must generate unique session identifiers using a FIPS 140-2 approved random number generator.'
  desc  "
    Sequentially generated session IDs can be easily guessed by an attacker. If an attacker can guess the session identifier, or can inject or manually insert session information, the valid user's application session can be compromised.

    Utilizing FIPS approved random number generators for the generation of unique session identifiers helps to protect against brute-force attacks to determine future session identifiers.

    Note: The UAG will only implement FIPS mode at install time, with the correct ova file build. The FIPS enabled ova file must be downloaded from the VMware site, and that ova file must be used to deploy the UAG into the environment.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    The information at the top of the page will show the build information (in year.month format), with a FIPS identifier if FIPS mode is enabled.

    Example:

    \"Unified Access Gateway Appliance v22.03 (FIPS)\"

    If the UAG was not installed with FIPS mode enabled, this is a finding.
  "
  desc  'fix', "
    The only way to enable FIPS mode on the UAG is by re-installing the appliance.

    Download the correct ova file from the VMware site, and re-deploy a new UAG appliance into the environment.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000234-ALG-000116'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000052'
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']

  result = uaghelper.runrestcommand('rest/v1/config/system')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)
    describe jsoncontent['fipsEnabled'] do
      it { should cmp true }
    end

    allowed = [input('secureRandomSource'), 'Default']
    describe 'Checking SecureRandom Source setting' do
      subject { allowed }
      it { should include jsoncontent['secureRandomSource'] }
    end
  end
end
