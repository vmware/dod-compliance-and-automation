control 'VCFE-9X-000014' do
  title 'The ESX host must use DOD-approved encryption to protect the confidentiality of network sessions.'
  desc  "
    Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

    Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., RDP), thereby providing a degree of confidentiality.
  "
  desc  'rationale', ''
  desc  'check', "
    From an ESX shell, run the following command:

    # esxcli system tls server get --show-profile-defaults --show-current-boot-profile

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.tls.server.get.CreateArgs()
    $arguments.showprofiledefaults = $true
    $arguments.showcurrentbootprofile = $true
    $esxcli.system.tls.server.get.invoke($arguments)

    Example result:

    Profile: NIST_2024
    Cipher List: ECDHE+AESGCM
    Cipher Suite: TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384
    Groups: prime256v1:secp384r1:secp521r1
    Protocol Versions: tls1.2,tls1.3
    Reboot Required: true

    If the TLS profile is not set to \"NIST_2024\" or is not the current boot profile, this is a finding.
  "
  desc  'fix', "
    TLS Profiles can be configured with vSphere Configuration Profiles or manually on each host for clusters not using vSphere Configuration Profiles.

    For ESX hosts in clusters managed with vSphere Configuration Profiles do the following:

    Note: These steps assume a vSphere Configuration Profile is already in use for the target cluster.

    From the vSphere Client, go to Host and Clusters.

    Select the vCenter Server >> Select the target cluster >> Configure >> Desired State >> Configuration >> Draft.

    Click \"Create Draft\" or \"Import from Host\" if a draft does not exist.

    Select system >> tls_server >> Configure Settings.

    Select \"NIST_2024\" from the drop down for profile and click \"Save\".

    Click \"Apply Changes\" and run through the pre-check to enforce the change.

    Note: Updating this setting through a vSphere Configuration Profile will place hosts into maintenance mode and perform a rolling reboot of all hosts in the cluster.

    For standalone hosts or clusters not managed with vSphere Configuration Profiles do the following:

    Prior to changing the TLS profile it is highly recommended to place the host in maintenance mode.

    From an ESX shell, run the following command:

    # esxcli system tls server set -p NIST_2024

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.tls.server.set.CreateArgs()
    $arguments.profile = \"NIST_2024\"
    $esxcli.system.tls.server.set.invoke($arguments)

    A reboot is required to complete the process of changing profiles.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000033-VMM-000140'
  tag satisfies: ['SRG-OS-000112-VMM-000560', 'SRG-OS-000113-VMM-000570', 'SRG-OS-000425-VMM-001710', 'SRG-OS-000426-VMM-001720']
  tag gid: 'V-VCFE-9X-000014'
  tag rid: 'SV-VCFE-9X-000014'
  tag stig_id: 'VCFE-9X-000014'
  tag cci: ['CCI-000068', 'CCI-001941', 'CCI-002420', 'CCI-002422']
  tag nist: ['AC-17 (2)', 'IA-2 (8)', 'SC-8 (2)']

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
  else
    vmhosts.each do |vmhost|
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $arguments = $esxcli.system.tls.server.get.CreateArgs(); $arguments.showcurrentbootprofile = $true; $esxcli.system.tls.server.get.invoke($arguments) | Select-Object -ExpandProperty Profile"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'NIST_2024' }
      end
    end
  end
end
