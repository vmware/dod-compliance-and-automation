control 'HZNC-8X-000128' do
  title 'The Horizon Client must not connect local USB devices to the remote desktop when they are plugged in.'
  desc  'While there may be legitimate reasons to pass USB devices to the desktop, these must be carefully analyzed for necessity. In general, USB devices must never be passed through, in keeping with long-standing DoD data loss prevention policies. As thumb drives are disallowed for physical PCs, so should they be for virtual desktops. Preventing USB pass-through can be accomplished in several ways, including natively in the Horizon Client.'
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration >> Scripting definitions.

    If \"Connect USB devices to the desktop or remote application when they are plugged in\" is set to \"Enabled\", this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration >> Scripting definitions.

    Ensure \"Connect USB devices to the desktop or remote application when they are plugged in\" is set to either \"Not configured\" or \"Disabled\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNC-8X-000128'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonclienthelper.setconnection

  reg = registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Client')

  if reg.has_property?('connectUSBOnInsert')
    describe reg do
      its('connectUSBOnInsert') { should cmp 'false' }
    end
  else
    describe reg do
      it { should_not have_property 'connectUSBOnInsert' }
    end
  end
end
