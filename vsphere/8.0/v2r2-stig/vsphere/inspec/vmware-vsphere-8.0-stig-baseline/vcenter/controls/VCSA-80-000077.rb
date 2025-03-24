control 'VCSA-80-000077' do
  title 'The vCenter Server must enable FIPS-validated cryptography.'
  desc 'FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules use authentication that meets DOD requirements.

In vSphere 6.7 and later, ESXi and vCenter Server use FIPS-validated cryptography to protect management interfaces and the VMware Certificate Authority (VMCA).

vSphere 7.0 Update 2 and later adds additional FIPS-validated cryptography to vCenter Server Appliance. By default, this FIPS validation option is disabled and must be enabled.

'
  desc 'check', 'From the vSphere Web Client, go to Developer Center >> API Explorer.

From the "Select API" drop-down menu, select appliance.

Expand system/security/global_fips >> GET.

Click "Execute" and then "Copy Response" to view the results.

Example response:

{
    "enabled": true
}

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Invoke-GetSystemGlobalFips

If global FIPS mode is not enabled, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Developer Center >> API Explorer.

From the "Select API" drop-down menu, select appliance.

Expand system/security/global_fips >> PUT.

In the response body under "Try it out" paste the following:

{
    "enabled": true
}

Click "Execute".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

$spec = Initialize-SystemSecurityGlobalFipsUpdateSpec -Enabled $true; Invoke-SetSystemGlobalFips -SystemSecurityGlobalFipsUpdateSpec $spec

Note: The vCenter server reboots after FIPS is enabled or disabled.'
  impact 0.7
  tag check_id: 'C-62657r934407_chk'
  tag severity: 'high'
  tag gid: 'V-258917'
  tag rid: 'SV-258917r961029_rule'
  tag stig_id: 'VCSA-80-000077'
  tag gtitle: 'SRG-APP-000172'
  tag fix_id: 'F-62566r934408_fix'
  tag satisfies: ['SRG-APP-000172', 'SRG-APP-000179', 'SRG-APP-000224', 'SRG-APP-000231', 'SRG-APP-000412', 'SRG-APP-000514', 'SRG-APP-000555', 'SRG-APP-000600', 'SRG-APP-000610', 'SRG-APP-000620', 'SRG-APP-000630', 'SRG-APP-000635']
  tag cci: ['CCI-000197', 'CCI-000803', 'CCI-001188', 'CCI-001199', 'CCI-001967', 'CCI-002450', 'CCI-003123']
  tag nist: ['IA-5 (1) (c)', 'IA-7', 'SC-23 (3)', 'SC-28', 'IA-3 (1)', 'SC-13 b', 'MA-4 (6)']

  command = 'Invoke-GetSystemGlobalFips | Select-Object -ExpandProperty enabled'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp 'True' }
  end
end
