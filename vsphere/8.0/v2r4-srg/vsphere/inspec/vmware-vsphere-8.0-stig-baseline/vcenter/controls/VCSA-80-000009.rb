control 'VCSA-80-000009' do
  title 'The vCenter Server must use DOD-approved encryption to protect the confidentiality of network sessions.'
  desc 'Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

In vCenter 8 Update 3, Transport Layer Security (TLS) Profiles were introduced that allow users to manage and configure TLS parameters for the vCenter server. Several TLS profiles are available by default but not all may be suitable for high security environments.'
  desc 'check', 'From the vSphere Client, go to Developer Center >> API Explorer.

Select "appliance" from the "Select API" drop down list then scroll down to the "tls/profiles/global" section.

Expand the GET call and click Execute and review the response for the configured global TLS profile.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Invoke-GetTlsProfilesGlobal

If the global TLS profile is not "NIST_2024", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Developer Center >> API Explorer.

Select "appliance" from the "Select API" drop down list then scroll down to the "tls/profiles/global" section.

Expand the PUT call and enter the following in the value box:

{
    "profile": "NIST_2024"
}

Click Execute and Continue to configure a new global TLS profile.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Invoke-SetProfilesGlobalAsync -TlsProfilesGlobalSetSpec (Initialize-TlsProfilesGlobalSetSpec -VarProfile NIST_2024)

To monitor the status of the operation the task id from the command output can be used with the "Invoke-GetTask" command. For example:

Invoke-GetTask -Task 66b247c2-fe02-4425-9338-1c88eb856138:com.vmware.appliance.tls.profiles.global'
  impact 0.5
  tag check_id: 'C-69901r1003611_chk'
  tag severity: 'medium'
  tag gid: 'V-265978'
  tag rid: 'SV-265978r1003613_rule'
  tag stig_id: 'VCSA-80-000009'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-69804r1003612_fix'
  tag cci: ['CCI-000068', 'CCI-000382', 'CCI-001184', 'CCI-001453', 'CCI-001941', 'CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422', 'CCI-002450']
  tag nist: ['AC-17 (2)', 'CM-7 b', 'SC-23', 'AC-17 (2)', 'IA-2 (8)', 'SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)', 'SC-13 b']

  command = 'Invoke-GetTlsProfilesGlobal | Select-Object -ExpandProperty profile'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp 'NIST_2024' }
  end
end
