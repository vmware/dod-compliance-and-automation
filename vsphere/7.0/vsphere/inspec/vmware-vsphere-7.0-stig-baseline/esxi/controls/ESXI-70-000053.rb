control 'ESXI-70-000053' do
  title 'SNMP must be configured properly on the ESXi host.'
  desc  'If SNMP is not being used, it must remain disabled. If it is being used, the proper trap destination must be configured. If SNMP is not properly configured, monitoring information can be sent to a malicious host that can then use this information to plan an attack.'
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command(s):

    # esxcli system snmp get

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHostSnmp | Select *

    If SNMP is not in use and is enabled, this is a finding.

    If SNMP is enabled and read only communities is set to \"public\", this is a finding.

    If SNMP is enabled and is not using v3 targets, this is a finding.

    Note: SNMP v3 targets can only be viewed and configured via the esxcli command.
  "
  desc 'fix', "
    To disable SNMP from an ESXi shell, run the following command(s):

    # esxcli system snmp set -e no

    or

    From a PowerCLI command prompt while connected to the ESXi Host:

    Get-VMHostSnmp | Set-VMHostSnmp -Enabled $false

    To configure SNMP for v3 targets, use the \"esxcli system snmp set\" command set locally on the host or remotely via PowerCLI.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000053'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmhostName = input('vmhostName')
  cluster = input('cluster')
  allhosts = input('allesxi')
  vmhosts = []

  unless vmhostName.empty?
    vmhosts = powercli_command("Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless cluster.empty?
    vmhosts = powercli_command("Get-Cluster -Name '#{cluster}' | Get-VMHost | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless allhosts == false
    vmhosts = powercli_command('Get-VMHost | Sort-Object Name | Select -ExpandProperty Name').stdout.split
  end

  if !vmhosts.empty?
    if "#{input('snmpEnabled')}" == 'false'
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
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
