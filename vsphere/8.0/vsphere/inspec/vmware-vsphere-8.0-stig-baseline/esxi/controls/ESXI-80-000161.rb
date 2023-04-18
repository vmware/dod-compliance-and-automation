control 'ESXI-80-000161' do
  title 'The ESXi host must maintain the confidentiality and integrity of information during transmission by exclusively enabling Transport Layer Security (TLS) 1.2.'
  desc  "
    TLS 1.0 and 1.1 are deprecated protocols with well-published shortcomings and vulnerabilities. TLS 1.2 should be enabled on all interfaces and SSLv3, TL 1.1, and 1.0 disabled, where supported.

    Mandating TLS 1.2 may break third-party integrations and add-ons to vSphere. Test these integrations carefully after implementing TLS 1.2 and roll back where appropriate.

    On interfaces where required functionality is broken with TLS 1.2, this finding is not applicable until such time as the third-party software supports TLS 1.2.

    Modify TLS settings in the following order:
    1. vCenter.
    2. ESXi.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Select the \"UserVars.ESXiVPsDisabledProtocols\" value and verify it is set to \"sslv3,tlsv1,tlsv1.1\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols

    If the \"UserVars.ESXiVPsDisabledProtocols\" setting is set to a value other than \"sslv3,tlsv1,tlsv1.1\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"UserVars.ESXiVPsDisabledProtocols\" value and configure it to \"sslv3,tlsv1,tlsv1.1\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols | Set-AdvancedSetting -Value \"sslv3,tlsv1,tlsv1.1\"
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000425-VMM-001710'
  tag satisfies: ['SRG-OS-000426-VMM-001720']
  tag gid: 'V-ESXI-80-000161'
  tag rid: 'SV-ESXI-80-000161'
  tag stig_id: 'ESXI-80-000161'
  tag cci: ['CCI-002420', 'CCI-002422']
  tag nist: ['SC-8 (2)']

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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'sslv3,tlsv1,tlsv1.1' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
