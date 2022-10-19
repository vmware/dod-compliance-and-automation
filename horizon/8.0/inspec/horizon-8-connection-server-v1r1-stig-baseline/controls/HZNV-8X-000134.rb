control 'HZNV-8X-000134' do
  title 'The Horizon Connection Server Instant Clone domain account must be configured with limited permissions.'
  desc  "
    Configuring the application to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

    If Instant Clones are utilized within the Horizon environment, an Active Directory User Account must be created that will be utilized to manage cloned Computer objects in Active Directory. Following least privilege best practices, this User Account must only be able to perform operations on Computer objects within a specified container in Active Directory.
  "
  desc  'rationale', ''
  desc  'check', "
    Log in to the Horizon Connection Server Console.

    From the left pane, navigate to Settings >> Instant Clone Domain Accounts.

    In the right pane, validate that the accounts listed are User accounts in Active Directory and have only the following permissions on the specified Instant Clone container:

    List Contents
    Read All Properties
    Write All Properties
    Read Permissions
    Reset Password
    Create Computer Objects
    Delete Computer Objects

    Ensure the permissions apply to the correct container and to all child objects of the container.

    If the Instant Clone domain account has more than the minimum required permissions, this is a finding.

    Note: If Instant Clones are not used, this is not applicable.
  "
  desc  'fix', "
    Log in to Active Directory Users and Computers.

    Navigate to the specified Instant Clone container.

    Set the permissions for the Instant Clone Domain Account to:

    List Contents
    Read All Properties
    Write All Properties
    Read Permissions
    Reset Password
    Create Computer Objects
    Delete Computer Objects

    Ensure the permissions apply to the correct container and to all child objects of the container.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000134'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonhelper.setconnection

  result = horizonhelper.getpowershellrestwithtoken('rest/config/v1/ic-domain-accounts')

  icaccts = JSON.parse(result.stdout)

  acctlist = "-----------------------------------------\n"
  icaccts['value'].each do |acct|
    acctlist += 'User: ' + acct['username'] + "\n"
  end
  acctlist += "-----------------------------------------\n"

  describe 'Manual Step - Validate Instant Clone Administrators' do
    skip "Manual validation of Instant Clone Administrators required:\n#{acctlist}"
  end
end
