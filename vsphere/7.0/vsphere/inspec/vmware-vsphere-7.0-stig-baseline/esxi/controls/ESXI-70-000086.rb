control 'ESXI-70-000086' do
  title 'The ESXi host must verify certificates for SSL syslog endpoints.'
  desc  'When sending syslog data to a remote host, ESXi can be configured to use any combination of TCP, UDP and SSL transports. When using SSL, the server certificate must be validated to ensure that the host is connecting to a valid syslog server.'
  desc  'rationale', ''
  desc  'check', "
    If SSL is not used for a syslog target, this is Not Applicable.

    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Select the \"Syslog.global.logCheckSSLCerts\" value and verify it is set to \"true\".

    or

    From a PowerCLI command prompt while connected to the ESXi host run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logCheckSSLCerts

    If the \"Syslog.global.logCheckSSLCerts\" setting is not set to \"true\", this is a finding
  "
  desc 'fix', "
    To configure SSL syslog endpoint certificate checking it must be turned on and also the trusted certificate chain must be added to ESXi's trusted store.

    Fom the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Select the \"Syslog.global.logCheckSSLCerts\" value and set it to \"true\".

    Copy the PEM formatted trusted CA certificate so that is accessible to the host and append the contents to /etc/vmware/ssl/castore.pem by running the follow command(s):

    # <path/to/cacert> >> /etc/vmware/ssl/castore.pem

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command(s):

    Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logCheckSSLCerts | Set-AdvancedSetting -Value \"true\"

    Copy the PEM formatted trusted CA certificate so that is accessible to the host.

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.security.certificatestore.add.CreateArgs()
    $arguments.filename = <path/to/cacert>
    $esxcli.system.security.certificatestore.add.Invoke($arguments)

  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000086'
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
        command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Syslog.global.logCheckSSLCerts | Select-Object -ExpandProperty Value"
        describe powercli_command(command) do
          its('stdout.strip') { should cmp 'true' }
        end
      else
        describe 'SSL syslog target not detected' do
          skip 'No SSL syslog targets, this check is N/A.'
        end
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
