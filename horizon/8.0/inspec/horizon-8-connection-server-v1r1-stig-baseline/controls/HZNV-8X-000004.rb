control 'HZNV-8X-000004' do
  title 'The Horizon Connection Server must be configured to use debug level logging.'
  desc  'To ensure that all security-relevant information and events are logged, the Horizon Connection Server must be configured to the "debug" logging level. This is the default value, but because it can be changed to other levels, this configuration must be verified and maintained.'
  desc  'rationale', ''
  desc  'check', "
    On the Horizon Connection Server, launch the Registry Editor.

    Traverse the registry tree to \"HKLM\\Software\\VMware, Inc.\\VMware VDM\".

    Locate the \"DebugEnabled\" key.

    If \"DebugEnabled\" does not exist, this is a finding.

    If \"DebugEnabled\" exists, and does not have a value of \"true\", this is a finding.
  "
  desc 'fix', "
    On the Horizon Connection Server, open the Start menu.

    Find and launch the \"Set Horizon Connection Server Log Levels\" shortcut. The precise location will vary depending on the Windows Server version and Start menu options.

    In the resulting command window, select option 2, \"View Debug\".

    Press any key to exit the command prompt window.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000016-AS-000013'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000004'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']

  horizonhelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\VMware, Inc.\\VMware VDM') do
    it { should have_property 'DebugEnabled' }
    its('DebugEnabled') { should cmp 'true' }
  end
end
