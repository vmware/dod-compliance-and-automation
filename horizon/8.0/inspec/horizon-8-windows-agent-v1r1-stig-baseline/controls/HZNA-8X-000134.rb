control 'HZNA-8X-000134' do
  title 'The Horizon Agent must not redirect client printers.'
  desc  "
    Data loss prevention is a primary concern for the DoD. Positive control of data must be maintained at all times, and data must only be allowed to flow over channels that are provided for that explicit purpose and are monitored appropriately.

    By default, the Horizon Client, Agent, and guest operating systems will coordinate to allow printers local to the client to be redirected over the Client connection and made available in the virtual desktop.

    This configuration must be modified to disallow printer redirection in order to protect sensitive DoD data from being maliciously, accidentally, or casually printed from the controlled environment.
  "
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> VMware Integrated Printing.

    If \"Do not redirect client printer(s)\" is set to \"Not Configured\" or \"Disabled\", this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> VMware Integrated Printing.

    Double-click the \"Do not redirect client printer(s)\" setting.

    Ensure \"Do not redirect client printer(s)\" is set to \"Enabled\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNA-8X-000134'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonagenthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\PrintRedir') do
    it { should have_property 'DisableClientPrinterRedir' }
    its('DisableClientPrinterRedir') { should cmp 1 }
  end
end
