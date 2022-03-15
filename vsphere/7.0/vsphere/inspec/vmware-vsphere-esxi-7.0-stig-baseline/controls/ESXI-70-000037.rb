control 'ESXI-70-000037' do
  title 'The ESXi host must use Active Directory for local user authentication.'
  desc  "Join ESXi hosts to an Active Directory (AD) domain to eliminate the
need to create and maintain multiple local user accounts. Using AD for user
authentication simplifies the ESXi host configuration, ensures password
complexity and reuse policies are enforced and reduces the risk of security
breaches and unauthorized access. Note: If the AD group \"ESX Admins\"
(default) exists then all users and groups that are assigned as members to this
group will have full administrative access to all ESXi hosts the domain."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> System >> Authentication Services. Verify the \"Directory Services
Type\" is set to \"Active Directory\".

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command:

    Get-VMHost | Get-VMHostAuthentication

    For systems that do not use Active Directory and have no local user
accounts, other than root and/or service accounts, this is not applicable.

    For systems that do not use Active Directory and do have local user
accounts, other than root and/or service accounts, this is a finding.

    If the Directory Services Type is not set to \"Active Directory\", this is
a finding.
  "
  desc 'fix', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> System >> Authentication Services. Click \"Join Domain...\" and
enter the AD domain to join, select the \"Using credentials radio
button and enter the credentials of an account with permissions to join
machines to AD (use UPN naming user@domain). Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command:

    Get-VMHost | Get-VMHostAuthentication | Set-VMHostAuthentication
-JoinDomain -Domain \"domain name\" -User \"username\" -Password \"password\"

    If any local user accounts are present besides root and service accounts
they can be deleted by going to the Host UI >> Manage >> Security & Users >>
Users.
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000104-VMM-000500'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000037'
  tag fix_id: nil
  tag cci: 'CCI-000764'
  tag nist: ['IA-2']

  list = %w(Joined Ok)
  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-VMHostAuthentication | Select-Object -ExpandProperty DomainMembershipStatus"
  describe powercli_command(command) do
    its('stdout.strip') { should be_in list }
  end
end
