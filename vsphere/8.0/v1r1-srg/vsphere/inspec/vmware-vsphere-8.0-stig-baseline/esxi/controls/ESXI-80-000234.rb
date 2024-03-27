control 'ESXI-80-000234' do
  title 'The ESXi host must enable strict x509 verification for SSL syslog endpoints.'
  desc  "
    When sending syslog data to a remote host via SSL, the ESXi host is presented with the endpoint's SSL server certificate. In addition to trust verification, configured elsewhere, this \"x509-strict\" option performs additional validity checks on CA root certificates during verification.

    These checks are generally not performed (CA roots are inherently trusted) and might cause incompatibilities with existing, misconfigured CA roots. The NIAP requirements in the Virtualization Protection Profile and Server Virtualization Extended Package, however, require even CA roots to pass validations.
  "
  desc  'rationale', ''
  desc  'check', "
    If SSL is not used for a syslog target, this is not applicable.

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Select the \"Syslog.global.certificate.strictX509Compliance\" value and verify it is set to \"true\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Syslog.global.certificate.strictX509Compliance

    If the \"Syslog.global.certificate.strictX509Compliance\" setting is not set to \"true\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"Syslog.global.certificate.strictX509Compliance\" value and configure it to \"true\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Syslog.global.certificate.strictX509Compliance | Set-AdvancedSetting -Value \"true\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-ESXI-80-000234'
  tag rid: 'SV-ESXI-80-000234'
  tag stig_id: 'ESXI-80-000234'
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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Syslog.global.certificate.strictX509Compliance | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'true' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
