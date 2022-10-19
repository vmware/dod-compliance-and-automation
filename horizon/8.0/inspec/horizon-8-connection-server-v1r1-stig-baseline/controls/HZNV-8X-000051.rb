control 'HZNV-8X-000051' do
  title 'The Horizon Connection Server must only use FIPS 140-2 validated cryptographic modules.'
  desc  "
    Encryption is only as good as the encryption modules utilized. Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms or poor implementation.

    The Horizon Connection Server can be configured to exclusively use FIPS 140-2 validated cryptographic modules but only at installation time, not post deployment. Reference VMware documentation for up-to-date requirements for enabling FIPS in Horizon View.
  "
  desc  'rationale', ''
  desc  'check', "
    On the Horizon Connection Server, launch the Registry Editor.

    Traverse the registry tree to \"HKLM\\Software\\VMware, Inc.\\VMware VDM\".

    Locate the \"FipsMode\" key.

    If \"FipsMode\" does not exist, this is a finding.

    If \"FipsMode\" does not have a value of \"1\", this is a finding.
  "
  desc 'fix', "
    FIPS mode can only be implemented during installation.

    Reinstall the Horizon Connection server and select the option to enable FIPS mode (after the IP configuration).

    Note: The Connection Server can only be installed in FIPS mode if Windows Server itself is running in FIPS mode.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000179-AS-000129'
  tag satisfies: ['SRG-APP-000224-AS-000152', 'SRG-APP-000416-AS-000140', 'SRG-APP-000439-AS-000274']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000051'
  tag cci: ['CCI-000803', 'CCI-001188', 'CCI-002418', 'CCI-002450']
  tag nist: ['IA-7', 'SC-13', 'SC-23 (3)', 'SC-8']

  horizonhelper.setconnection

  result = horizonhelper.getpowershellrestwithtoken('rest/config/v1/environment-properties')

  json = JSON.parse(result.stdout)

  describe json['fips_mode_enabled'] do
    it { should cmp true }
  end
end
