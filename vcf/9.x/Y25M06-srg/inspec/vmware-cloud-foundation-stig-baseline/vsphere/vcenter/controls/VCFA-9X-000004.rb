control 'VCFA-9X-000004' do
  title 'The VMware Cloud Foundation vCenter Server must protect the confidentiality of network sessions.'
  desc  "
    Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

    In vCenter 8 Update 3 Transport Layer Security (TLS) Profiles were introduced that allow users to manage and configure TLS parameters for the vCenter server. Several TLS profiles are available by default but not all may be suitable for high security environments.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Developer Center >> API Explorer.

    Select \"appliance\" from the \"Select API\" drop down list then scroll down to the \"tls/profiles/global\" section.

    Expand the GET call and click Execute and review the response for the configured global TLS profile.

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Invoke-GetTlsProfilesGlobal

    If the global TLS profile is not \"NIST_2024\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Developer Center >> API Explorer.

    Select \"appliance\" from the \"Select API\" drop down list then scroll down to the \"tls/profiles/global\" section.

    Expand the PUT call and enter the following in the value box:

    {
        \"profile\": \"NIST_2024\"
    }

    Click Execute and Continue to configure a new global TLS profile.

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Invoke-ApplianceTlsProfilesGlobalSetTask -applianceTlsProfilesGlobalSetSpec (Initialize-ApplianceTlsProfilesGlobalSetSpec -VarProfile NIST_2024)

    To monitor the status of the operation the task id from the command output can be used with the \"Invoke-GetTask\" command. For example:

    Invoke-GetTask -Task 66b247c2-fe02-4425-9338-1c88eb856138:com.vmware.appliance.tls.profiles.global
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000014'
  tag satisfies: ['SRG-APP-000156', 'SRG-APP-000157', 'SRG-APP-000219', 'SRG-APP-000440', 'SRG-APP-000441', 'SRG-APP-000442', 'SRG-APP-000560', 'SRG-APP-000565', 'SRG-APP-000645']
  tag gid: 'V-VCFA-9X-000004'
  tag rid: 'SV-VCFA-9X-000004'
  tag stig_id: 'VCFA-9X-000004'
  tag cci: ['CCI-000068', 'CCI-000382', 'CCI-001184', 'CCI-001453', 'CCI-001941', 'CCI-002420', 'CCI-002421', 'CCI-002422']
  tag nist: ['AC-17 (2)', 'CM-7 b', 'IA-2 (8)', 'SC-23', 'SC-8 (1)', 'SC-8 (2)']

  command = 'Invoke-GetTlsProfilesGlobal -Confirm:$false | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue'
  result = powercli_command(command).stdout.strip

  if result.blank?
    describe "No results returned from command: #{command} . Troubleshoot issue and rerun scan." do
      skip "No results returned from command: #{command} . Troubleshoot issue and rerun scan."
    end
  else
    describe 'The vCenter TLS Profile:' do
      subject { json(content: result) }
      its(['Profile']) { should cmp 'NIST_2024' }
    end
  end
end
