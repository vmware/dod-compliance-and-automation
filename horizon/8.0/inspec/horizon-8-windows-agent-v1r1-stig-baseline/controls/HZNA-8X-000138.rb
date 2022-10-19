control 'HZNA-8X-000138' do
  title 'The Horizon Agent must block USB mass storage.'
  desc  "
    The Horizon Agent has the capability to granularly control what, if any, USB devices are allowed to be passed from the local client to the agent on the virtual desktop. By default, Horizon blocks certain device families from being redirected to the remote desktop or application. For example, HID (human interface devices) and keyboards are blocked from appearing in the guest as released BadUSB code targets USB keyboard devices.

    While there are legitimate reasons to pass USB devices to the desktop, these must be carefully analyzed for necessity. At a minimum, USB Mass Storage devices must never be passed through, in keeping with long-standing DoD data loss prevention policies. As thumb drives are disallowed for physical PCs, so should they be for virtual desktops. This can be accomplished in several ways, including natively in the Horizon Agent.
  "
  desc  'rationale', ''
  desc  'check', "
    USB mass storage devices can be blocked in a number of ways:

    1. The desktop OS
    2. A third party DLP solution
    3. The \"USB Redirection\" optional Horizon Agent feature not being selected during install on any VDI image
    4. On the Connection Server via individual pool policies or global policies

    If any of these methods are already employed, the risk is already addressed and this control is not applicable.

    If USB devices are not otherwise blocked, the Horizon Agent must be configured to block storage devices.

    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> View USB Configuration.

    If \"Include Device Family\" is set to \"Enabled\" and includes the value \"storage\", this is a finding.

    If both \"Exclude All Devices\" is not set to \"Enabled\", and \"Exclude Device Family\" is not set to \"Enabled\" with the value \"storage\" included, this is a finding.

    If either \"Exclude All Devices\" is set to \"Enabled\", or \"Exclude Device Family\" is set to \"Enabled\" and includes the value \"o:storage\", this is not a finding.
  "
  desc 'fix', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> View USB Configuration.

    First ensure \"Include Device Family\" is set to either \"Not Enabled\" or \"Disabled\", or does not include the value \"storage\".

    Then ensure one of the following options is configured:

    Option 1:

    > Ensure \"Exclude All Devices\" is set to \"Enabled\".

    Option 2:

    > Ensure \"Exclude Device Family\" is set to \"Enabled\" and includes the value \"o:storage\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNA-8X-000138'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonagenthelper.setconnection

  reg = registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Agent\\USB')

  if reg.has_property?('IncludeFamily')
    describe reg do
      its('IncludeFamily') { should_not include 'storage' }
    end
  end

  if reg.has_property?('ExcludeFamily')
    describe reg do
      its('ExcludeFamily') { should include 'o:storage' }
    end
  else
    describe reg do
      its('ExcludeAllDevices') { should cmp 'true' }
    end
  end
end
