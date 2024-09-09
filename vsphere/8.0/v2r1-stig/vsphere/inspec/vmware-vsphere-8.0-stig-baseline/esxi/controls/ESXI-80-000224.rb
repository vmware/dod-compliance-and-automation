control 'ESXI-80-000224' do
  title 'The ESXi host must verify certificates for SSL syslog endpoints.'
  desc 'When sending syslog data to a remote host, ESXi can be configured to use any combination of TCP, UDP, and SSL transports. When using SSL, the server certificate must be validated to ensure that the host is connecting to a valid syslog server.'
  desc 'check', 'If SSL is not used for a syslog target, this is not applicable.

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Syslog.global.certificate.checkSSLCerts" value and verify it is set to "true".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.certificate.checkSSLCerts

If the "Syslog.global.certificate.checkSSLCerts" setting is not set to "true", this is a finding.'
  desc 'fix', %q(To configure SSL syslog endpoint certificate checking, it must be turned on and the trusted certificate chain must be added to ESXi's trusted store.

From the vSphere Client go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "Syslog.global.certificate.checkSSLCerts" value and configure it to "true".

Copy the PEM formatted trusted CA certificate so that is accessible to the host and append the contents to /etc/vmware/ssl/castore.pem by running the following command:

# <path/to/cacert> >> /etc/vmware/ssl/castore.pem

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.certificate.checkSSLCerts | Set-AdvancedSetting -Value "true"

Copy the PEM formatted trusted CA certificate so that is accessible to the host.

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.security.certificatestore.add.CreateArgs()
$arguments.filename = <path/to/cacert>
$esxcli.system.security.certificatestore.add.Invoke($arguments))
  impact 0.5
  tag check_id: 'C-62519r1003536_chk'
  tag severity: 'medium'
  tag gid: 'V-258779'
  tag rid: 'SV-258779r1003572_rule'
  tag stig_id: 'ESXI-80-000224'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62428r1003537_fix'
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
    vmhosts.each do |vmhost|
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Syslog.global.logHost | Where {$_.Value -match \"ssl\"} | Select-Object -ExpandProperty Value"
      syslogservers = powercli_command(command).stdout

      if !syslogservers.empty?
        command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Syslog.global.certificate.checkSSLCerts | Select-Object -ExpandProperty Value"
        describe powercli_command(command) do
          its('stdout.strip') { should cmp 'true' }
        end
      else
        impact 0.0
        describe '' do
          skip 'No SSL syslog targets found, this check is not applicable.'
        end
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
