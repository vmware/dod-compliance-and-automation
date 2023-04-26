control 'HZNC-8X-000129' do
  title 'The Horizon Client must not connect local USB devices to the remote desktop on launch.'
  desc  'While there may be legitimate reasons to pass USB devices to the desktop, these must be carefully analyzed for necessity. In general, USB devices must never be passed through, in keeping with long-standing DoD data loss prevention policies. As thumb drives are disallowed for physical PCs, so should they be for virtual desktops. Preventing USB pass-through can be accomplished in several ways, including natively in the Horizon Client.'
  desc  'rationale', ''
  desc  'check', "
    USB can be blocked in a number of ways:

    1. The desktop OS
    2. A third party DLP solution
    3. The \"USB Redirection\" optional Horizon Agent feature not being selected during install on any VDI image
    4. On the Connection Server via individual pool policies or global policies

    If any of these methods are already employed, the risk is already addressed and this control is not applicable.

    If USB devices are not otherwise blocked, the Horizon Client must be configured to block USB devices.

    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration >> Scripting definitions.

    If \"Connect all USB devices to the desktop or remote application on launch\" is set to \"Enabled\", this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration >> Scripting definitions.

    Ensure \"Connect all USB devices to the desktop or remote application on launch\" is set to either \"Not configured\" or \"Disabled\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-HZNC-8X-000129'
  tag rid: 'SV-HZNC-8X-000129'
  tag stig_id: 'HZNC-8X-000129'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonclienthelper.setconnection

  reg = registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Client')

  if reg.has_property?('connectUSBOnStartup')
    describe reg do
      its('connectUSBOnStartup') { should cmp 'false' }
    end
  else
    describe reg do
      it { should_not have_property 'connectUSBOnStartup' }
    end
  end
end
