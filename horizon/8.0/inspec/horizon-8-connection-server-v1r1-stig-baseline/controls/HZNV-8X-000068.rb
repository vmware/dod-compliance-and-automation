control 'HZNV-8X-000068' do
  title 'The Horizon Connection Server must protect log files from unauthorized access.'
  desc  "
    Error logs can contain sensitive information about system errors and system architecture that need to be protected from unauthorized access and modification.

    By default, Horizon Connection Server logs are only accessible to local Windows Administrators. This configuration must be verified and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    On the Horizon Connection Server, navigate to \"<install_directory>\\ProgramData\\VMware\\VDM\".

    Right-click the \"logs\" folder and select \"Properties\".

    Change to the \"Security\" tab.

    By default, only built-in system accounts such as \"SYSTEM\" and \"NETWORK SERVICE\" plus the local \"Administrators\" group have access to the \"logs\" folder.

    If any other groups or users have any permissions on this folder, this is a finding.
  "
  desc 'fix', "
    On the Horizon Connection Server, navigate to \"<install_directory>\\ProgramData\\VMware\\VDM\".

    Right-click the \"logs\" folder and select \"Properties\".

    Change to the \"Security\" tab.

    Click \"Edit…\".

    Highlight any groups or users that are not built-in system administrative accounts or the local \"Administrators\" group.

    Click \"Remove\".

    Click \"OK\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000267-AS-000170'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000068'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  horizonhelper.setconnection

  raw_security = powershell("(Get-Acl -Path #{input('vdmpath')}).AccessToString")

  # clean results cleans up the extra line breaks, converts previous string to array
  clean_security = raw_security.stdout.lines.collect(&:strip)

  # Order may be different, so can't do a straight compare.... loop through each.
  allowed = input('vmware_vdm_perms')

  clean_security.each do |item|
    describe allowed do
      it { should include item }
    end
  end
end
