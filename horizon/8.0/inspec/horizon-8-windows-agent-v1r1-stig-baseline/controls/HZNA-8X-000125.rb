control 'HZNA-8X-000125' do
  title 'The Horizon Agent must only run allowed scripts on user connect.'
  desc  "
    The Horizon Agent has the capability to run scripts when a user connects, disconnects, or reconnects. While this can be useful in setting up a user environment, in certain circumstances the running of such scripts should be delegated to native windows capabilities where possible. These settings are powerful and can serve as a potential space for a privileged attacker to persist.

    By default, this setting is unconfigured. Should the site require this setting, ensure it is audited and its configuration valid at all times.
  "
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Agent Configuration.

    Double-click the \"CommandsToRunOnConnect\" setting.

    If \"CommandsToRunOnConnect\" is set to either \"Not Configured\" or \"Disabled\", this is not a finding.

    Click the \"Show...\" button next to \"Commands\". If there are any commands listed that are not required, expected, and approved, this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Agent Configuration.

    Double-click the \"CommandsToRunOnConnect\" setting.

    Option 1:

    > Ensure \"CommandsToRunOnConnect\" is set to \"Disabled\".

    > Click \"OK\".

    Option 2:

    > Ensure \"CommandsToRunOnConnect\" is set to \"Enabled\".

    > Click the \"Show...\" button next to \"Commands\". Highlight each unapproved command and press the \"Delete\" key.

    > Click \"OK\".

    > Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNA-8X-000125'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonagenthelper.setconnection

  regexist = registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Agent\\Configuration\\CommandsToRunOnConnect')

  reg = json(command: '$path = "HKLM:\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Agent\\Configuration\\CommandsToRunOnConnect";
                          Get-Item -Path $path |
                          Select-Object -ExpandProperty property |
                          ForEach-Object { New-Object psobject -Property @{"$_"=(Get-ItemProperty -Path $path -Name $_).$_}} |
                          ConvertTo-Json').params

  describe.one do
    describe regexist do
      it { should_not exist }
    end

    describe input('allowedConnectScripts') do
      reg.each do |_key, val|
        it { should include val }
      end
    end
  end
end
