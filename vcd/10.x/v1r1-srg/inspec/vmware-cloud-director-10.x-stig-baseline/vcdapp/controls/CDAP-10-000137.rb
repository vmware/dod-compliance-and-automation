control 'CDAP-10-000137' do
  title 'Cloud Director must disable the local system administrator account.'
  desc  "
    VMware Cloud Director provides a self-contained identity provider (IDP) for user accounts, which are created and maintained in the VMware Cloud Director database. While not inherently vulnerable in a system configured with limited network access to the database, these accounts do not provide the kinds of password management features required in DoD. To discourage brute-force attacks, local accounts should be subject to password retry limits and account lockout rules.

    Service providers must carefully weigh the benefits and risks of continuing to use local accounts for system administrators, and carefully control which source IP addresses can authenticate to an organization's cloud URL if local system administrator accounts are configured. Consider eliminating or at least limiting the use of this identity provider for system administrator accounts.

    A new installation of VMware Cloud Director creates a local system administrator account. In the default configuration, VMware Cloud Director requires at least one system administrator account to remain local. A service provider who has enabled the System organization to use the vSphere SSO service - a SAML IDP, or LDAP, can configure VMware Cloud Director to operate with no local system administrator accounts.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vcloud-director/bin/cell-management-tool manage-config -n local.sysadmin.disabled -l

    Expected result:

    Property \"local.sysadmin.disabled\" has value \"true\"

    If \"local.sysadmin.disabled\" does not exist or is set to false, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command:

    # /opt/vmware/vcloud-director/bin/cell-management-tool manage-config -n local.sysadmin.disabled -v true

    Note: This does not disable local accounts for other organizations.

    Note: In a system that has no local system administrator accounts, cell management tool commands that require you to specify system administrator credentials must use the -i --pid option instead, supplying the cell's process ID in pid.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CDAP-10-000137'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command('/opt/vmware/vcloud-director/bin/cell-management-tool manage-config -n local.sysadmin.disabled -l') do
    its('stdout.strip') { should cmp 'Property "local.sysadmin.disabled" has value "true"' }
  end
end
