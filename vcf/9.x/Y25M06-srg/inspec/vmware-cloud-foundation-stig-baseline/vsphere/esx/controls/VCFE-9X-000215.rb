control 'VCFE-9X-000215' do
  title 'The ESX host must disable Simple Network Management Protocol (SNMP) v1 and v2c.'
  desc  'If SNMP is not being used, it must remain disabled. If it is being used, the proper trap destination must be configured. If SNMP is not properly configured, monitoring information can be sent to a malicious host that can use this information to plan an attack.'
  desc  'rationale', ''
  desc  'check', "
    From an ESX shell, run the following command:

    # esxcli system snmp get

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHostSnmp | Select *

    If SNMP is not in use and is enabled, this is a finding.

    If SNMP is enabled and is not using v3 targets with authentication, this is a finding.

    Note: SNMP v3 targets can only be viewed and configured via the \"esxcli\" command.
  "
  desc 'fix', "
    To disable SNMP from an ESX shell, run the following command:

    # esxcli system snmp set -e no

    or

    From a PowerCLI command prompt while connected to the ESX Host:

    Get-VMHostSnmp | Set-VMHostSnmp -Enabled $false
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFE-9X-000215'
  tag rid: 'SV-VCFE-9X-000215'
  tag stig_id: 'VCFE-9X-000215'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmhostName = input('esx_vmhostName')
  cluster = input('esx_cluster')
  allhosts = input('esx_allHosts')
  vmhosts = []

  unless vmhostName.blank?
    vmhosts = powercli_command("Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless cluster.blank?
    vmhosts = powercli_command("Get-Cluster -Name '#{cluster}' | Get-VMHost | Sort-Object Name | Select -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless allhosts == false
    vmhosts = powercli_command('Get-VMHost | Sort-Object Name | Select -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")
  end

  if vmhosts.blank?
    describe 'No ESX hosts found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.' do
      skip 'No ESX hosts found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.'
    end
  elsif "#{input('esx_snmpEnabled')}" == 'false'
    vmhosts.each do |vmhost|
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.snmp.get.Invoke() | Select-Object -ExpandProperty enable"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'false' }
      end
    end
  else
    describe 'SNMP Enabled' do
      skip 'Manually verify SNMP v3 is configured correctly and v2 is not used.'
    end
  end
end
