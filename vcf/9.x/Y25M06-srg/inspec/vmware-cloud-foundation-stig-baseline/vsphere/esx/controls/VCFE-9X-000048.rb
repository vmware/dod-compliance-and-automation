control 'VCFE-9X-000048' do
  title 'The ESX host must uniquely identify and must authenticate organizational users by using Active Directory.'
  desc  "
    Join ESX hosts to an Active Directory domain to eliminate the need to create and maintain multiple local user accounts. Using Active Directory for user authentication simplifies the ESX host configuration, ensures password complexity and reuse policies are enforced, and reduces the risk of security breaches and unauthorized access.

    Note: If the Active Directory group \"ESX Admins\" (default) exists, all users and groups assigned as members to this group will have full administrative access to all ESX hosts in the domain.
  "
  desc  'rationale', ''
  desc  'check', "
    For systems that do not use Active Directory and have no local user accounts other than root and/or service accounts, this is not applicable.

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Authentication Services.

    Verify the \"Directory Services Type\" is set to \"Active Directory\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-VMHostAuthentication

    For systems that do not use Active Directory and do have local user accounts, other than root and/or service accounts, this is a finding.

    If the \"Directory Services Type\" is not set to \"Active Directory\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Authentication Services.

    Click \"Join Domain...\" and enter the AD domain to join.

    Select the \"Using credentials\" radio button and enter the credentials of an account with permissions to join machines to AD (use UPN naming \"user@domain\"). Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-VMHostAuthentication | Set-VMHostAuthentication -JoinDomain -Domain \"domain name\" -User \"username\" -Password \"password\"

    If any local user accounts are present besides root and service accounts, delete them by going to Host UI >> Manage >> Security & Users >> Users.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000104-VMM-000500'
  tag satisfies: ['SRG-OS-000109-VMM-000550', 'SRG-OS-000123-VMM-000620']
  tag gid: 'V-VCFE-9X-000048'
  tag rid: 'SV-VCFE-9X-000048'
  tag stig_id: 'VCFE-9X-000048'
  tag cci: ['CCI-000764', 'CCI-001682', 'CCI-004045']
  tag nist: ['AC-2 (2)', 'IA-2', 'IA-2 (5)']

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
  elsif input('esx_adJoined')
    list = ['Joined', 'Ok']
    vmhosts.each do |vmhost|
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostAuthentication | Select-Object -ExpandProperty DomainMembershipStatus"
      describe powercli_command(command) do
        its('stdout.strip') { should be_in list }
      end
    end
  else
    vmhosts.each do |vmhost|
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostAuthentication | Select-Object -ExpandProperty DomainMembershipStatus"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '' }
      end
    end
  end
end
