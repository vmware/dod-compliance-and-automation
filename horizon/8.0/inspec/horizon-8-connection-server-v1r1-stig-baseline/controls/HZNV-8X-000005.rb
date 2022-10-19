control 'HZNV-8X-000005' do
  title 'The Horizon Connection Server administrators must be limited in terms of quantity, scope, and permissions.'
  desc  "
    Role based access and least privilege are two fundamental security concepts that must be properly implemented in Horizon Connection Server to ensure the correct users and groups have the appropriate permissions on the relevant objects.

    Horizon Connection Server allows for assigning roles (pre-defined sets of permissions) to specific users and groups on a specific Access Group (set of objects).

    Administrators must ensure that minimal permissions are assigned to the correct entities, in the right scope, and that the permissions remain unchanged over time.
  "
  desc  'rationale', ''
  desc  'check', "
    Log in to the Horizon Connection Server Console.

    From the left pane, navigate to Settings >> Administrators.

    From the \"Administrators and Groups\" tab, review each user and group in the left pane and their associated roles in the right pane.

    Permissions must be as restrictive as possible and their scope (Access Group) as limited as possible. Ensure no user or group has unnecessary permissions and that their Access Group is appropriately limited. Pay special attention to the \"Local Administrator\" and \"Administrator\" roles on the root Access Group as those roles have total control over the local and global environment, respectively. Anyone with any privilege can log in to the Console and view potentially sensitive configurations, system details, and events.

    If there are any users or groups that should not be treated as trusted \"Administrators\" of the Horizon system, this is a finding.

    If any user or group has permissions that are more permissive than the minimum necessary, this is a finding.
  "
  desc  'fix', "
    Log in to the Horizon Connection Server Console.

    From the left pane, navigate to Settings >> Administrators.

    To remove users or groups:

    > From the \"Administrators and Groups\" tab, select the unnecessary users or groups in the left pane and click the \"Remove User or Group\" button.

    > Click \"OK'\" to confirm removal.

    To modify assigned permissions:

    > From the \"Administrators and Groups\" tab, select the appropriate user or group in the left pane.

    > In the right pane, select the role to remove and click \"Remove Permission\".

    > Click \"OK\" to confirm removal.

    To create a new role with more limited permissions:

    > From the \"Role Permissions\" tab, click \"Add Role\", then provide a descriptive name and select the minimum required permissions.

    > Click \"OK\", then highlight the new role.

    > Click \"Add Permission\".

    > Click \"Add\" and find the relevant user(s).

    >Click \"OK\".

    >Click \"Finish\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag satisfies: ['SRG-APP-000118-AS-000078', 'SRG-APP-000121-AS-000081', 'SRG-APP-000122-AS-000082', 'SRG-APP-000123-AS-000083', 'SRG-APP-000290-AS-000174', 'SRG-APP-000315-AS-000094', 'SRG-APP-000340-AS-000185', 'SRG-APP-000380-AS-000088']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000005'
  tag cci: ['CCI-000162', 'CCI-000213', 'CCI-001493', 'CCI-001494', 'CCI-001495', 'CCI-001496', 'CCI-001813', 'CCI-002235', 'CCI-002314']
  tag nist: ['AC-17 (1)', 'AC-3', 'AC-6 (10)', 'AU-9', 'AU-9 (3)', 'CM-5 (1)']

  horizonhelper.setconnection

  # Get the list of Access Groups and related Permissions
  aglistraw = horizonhelper.getpowershellrestwithsession('view-vlsi/rest/v1/AccessGroup/List')
  aglist = JSON.parse(aglistraw.stdout)

  aglist['value'].each do |ag|
    # Get Permission Info for each Access Group
    # Permission data comes back unquoted with spaces separating each item, so we need to build a string array for the Body to POST.
    body = %(["#{ag['data']['permissions'].gsub(' ', '","')}"])
    piraw = horizonhelper.postpowershellrestwithsession('view-vlsi/rest/v1/Permission/GetInfos', body)

    pi = JSON.parse(piraw.stdout)

    permlist = ''
    pi['value'].each do |perm|
      permlist += "-----------------------------------------\n"
      permlist += 'User: ' + perm['namesData']['userOrGroupName'] + "\n"
      permlist += 'Role: ' + perm['namesData']['roleName'] + "\n"
      permlist += 'Group: ' + perm['namesData']['accessGroupName'] + "\n"
    end
    permlist += "-----------------------------------------\n"

    describe 'Manual Step - Validate Permissions' do
      skip "Manual validation of permissions required:\n#{permlist}"
    end
  end
end
