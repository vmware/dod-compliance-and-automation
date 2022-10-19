control 'HZNV-8X-000113' do
  title 'All Horizon components must be running supported versions.'
  desc  "
    Security flaws with software applications are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities.

    Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes) to production systems after thorough testing of the patches within a lab environment.

    Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the Horizon Connection Server administrative interface as an administrator.

    Navigate to Servers, and select the \"Connection Servers\" tab.

    Analyze the \"Version\" column information for each Connection Server listed.

    Cross-reference the build information displayed within VMware's site to identify, at minimum, the oldest supported build available.

    If the installed version of Horizon is not supported by VMware, this is a finding.
  "
  desc 'fix', ' Install or upgrade each Horizon Connection Server to a VMware supported version.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000456-AS-000266'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000113'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']

  horizonhelper.setconnection

  result = horizonhelper.getpowershellrestwithtoken('rest/config/v2/environment-properties')

  json = JSON.parse(result.stdout)

  describe json['local_connection_server_version'] do
    it { should cmp input('expectedVersion') }
  end
end
