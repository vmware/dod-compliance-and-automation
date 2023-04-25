control 'HZNC-8X-000137' do
  title 'The Horizon Client must not redirect client printers.'
  desc  "
    Data loss prevention is a primary concern for the DoD. Positive control of data must be maintained at all times, and data must only be allowed to flow over channels that are provided for that explicit purpose and are monitored appropriately. By default, the Horizon Client, Agent, and guest operating systems will coordinate to allow printers local to the client to be redirected over the Client connection and made available in the virtual desktop.

    This configuration must be modified to disallow printer redirection in order to protect sensitive DoD data from being maliciously, accidentally, or casually printed from the controlled environment.
  "
  desc  'rationale', ''
  desc  'check', "
    Printer redirection can be disabled in a number of ways:

    1. The desktop OS
    2. A third party DLP solution
    3. The \"VMware Integrated Printing\" optional Horizon Agent feature not being selected during install on any VDI image.

    If any of these methods are already employed, the risk is already addressed and this control is not applicable.

    If printer redirection is not otherwise blocked, the Horizon Client must be configured to block printer redirection.

    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration >> VMware Integrated Printing.

    If \"Do not redirect client printer(s)\" is not set to \"Enabled\", this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration >> VMware Integrated Printing.

    Ensure \"Do not redirect client printer(s)\" is set to \"Enabled\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-HZNC-8X-000137'
  tag rid: 'SV-HZNC-8X-000137'
  tag stig_id: 'HZNC-8X-000137'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonclienthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\PrintRedir') do
    it { should have_property 'DisableClientPrinterRedir' }
    its('DisableClientPrinterRedir') { should cmp '1' }
  end
end
