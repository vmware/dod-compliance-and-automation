control 'ESXI-70-000037' do
  title 'The ESXi host must use Active Directory for local user authentication.'
  desc 'Join ESXi hosts to an Active Directory domain to eliminate the need to create and maintain multiple local user accounts. Using Active Directory for user authentication simplifies the ESXi host configuration, ensures password complexity and reuse policies are enforced, and reduces the risk of security breaches and unauthorized access.

Note: If the Active Directory group "ESX Admins" (default) exists, all users and groups assigned as members to this group will have full administrative access to all ESXi hosts in the domain.

'
  desc 'check', 'For systems that do not use Active Directory and have no local user accounts other than root and/or service accounts, this is not applicable.

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Authentication Services.

Verify the "Directory Services Type" is set to "Active Directory".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-VMHostAuthentication

For systems that do not use Active Directory and do have local user accounts, other than root and/or service accounts, this is a finding.

If the Directory Services Type is not set to "Active Directory", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Authentication Services.

Click "Join Domain..." and enter the AD domain to join.

Select the "Using credentials" radio button and enter the credentials of an account with permissions to join machines to AD (use UPN naming "user@domain"). Click "OK".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-VMHostAuthentication | Set-VMHostAuthentication -JoinDomain -Domain "domain name" -User "username" -Password "password"

If any local user accounts are present besides root and service accounts, delete them by going to Host UI >> Manage >> Security & Users >> Users.'
  impact 0.3
  tag check_id: 'C-60077r885985_chk'
  tag severity: 'low'
  tag gid: 'V-256402'
  tag rid: 'SV-256402r885987_rule'
  tag stig_id: 'ESXI-70-000037'
  tag gtitle: 'SRG-OS-000104-VMM-000500'
  tag fix_id: 'F-60020r885986_fix'
  tag satisfies: ['SRG-OS-000104-VMM-000500', 'SRG-OS-000109-VMM-000550', 'SRG-OS-000112-VMM-000560', 'SRG-OS-000113-VMM-000570']
  tag cci: ['CCI-000764', 'CCI-000770', 'CCI-001941', 'CCI-001942']
  tag nist: ['IA-2', 'IA-2 (5)', 'IA-2 (8)', 'IA-2 (9)']

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
    list = ['Joined', 'Ok']
    vmhosts.each do |vmhost|
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostAuthentication | Select-Object -ExpandProperty DomainMembershipStatus"
      describe powercli_command(command) do
        its('stdout.strip') { should be_in list }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
