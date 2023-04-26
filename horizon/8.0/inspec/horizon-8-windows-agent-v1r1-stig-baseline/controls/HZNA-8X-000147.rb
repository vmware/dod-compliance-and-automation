control 'HZNA-8X-000147' do
  title 'The Horizon Agent must disable access to a VDI PCoIP session from a vSphere console.'
  desc  "
    Data loss prevention is a primary concern for the DoD. Positive control of data must be maintained at all times, and data must only be allowed to be viewed by authorized individuals.

    By default, the Horizon Agent does not allow access to a PCoIP session from a vSphere console. This configuration option must be validated and maintained over time.

    Note: This control applies to VDI PCoIP sessions, and not RDSH sessions.
  "
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> PCoIP Session Variables >> Not Overridable Administrator Settings.

    If \"Enable access to a PCoIP session from a vSphere console\" is not set to \"Disabled\", this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> PCoIP Session Variables >> Not Overridable Administrator Settings.

    Double-click the \"Enable access to a PCoIP session from a vSphere console\" setting.

    Ensure \"Enable access to a PCoIP session from a vSphere console\" is set to \"Disabled\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-HZNA-8X-000147'
  tag rid: 'SV-HZNA-8X-000147'
  tag stig_id: 'HZNA-8X-000147'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonagenthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Teradici\\PCoIP\\pcoip_admin') do
    it { should have_property 'pcoip.enable_console_access' }
    its('pcoip.enable_console_access') { should cmp 0 }
  end
end
