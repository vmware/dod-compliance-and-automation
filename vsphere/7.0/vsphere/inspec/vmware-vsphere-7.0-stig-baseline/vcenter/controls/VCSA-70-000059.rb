control 'VCSA-70-000059' do
  title 'The vCenter Server must uniquely identify and authenticate users or processes acting on behalf of users.'
  desc  "
    To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

    Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following.

    (i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and
    (ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

    Using Active Directory or an identity provider for authentication provides more robust account management capabilities and accountability.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Web Client go to Administration >> Single Sign On >> Configuration >> Identity Provider.

    If the identity provider type is \"embedded\" and there is no identity source of type \"Active Directory\" (either Windows Integrated Authentication or LDAP), this is a finding.

    If the identity provider type is \"Microsoft ADFS\" or another supported identity provider, this is NOT a finding.
  "
  desc 'fix', "
    When using the embedded identity provider type perform the following:

    From the vSphere Web Client go to Administration >> Single Sign On >> Configuration >> Identity Provider >> Identity Sources.

    Click \"Add\".

    Select either \"Active Directory over LDAP\" or \"Active Directory (Windows Integrated Authentication)\" and configure appropriately.

    Note: Windows Integrated Authentication requires that the vCenter server be joined to AD before configuration via Administration >> Single Sign On >> Configuration >> Identity Provider >> Active Directory Domain.

    OR

    To change the identity provider type to a 3rd party identity provider such as Microsoft ADFS perform the following:

    From the vSphere Web Client go to Administration >> Single Sign On >> Configuration >> Identity Provider.

    Click \"Change Identity Provider\".

    Select \"Microsoft ADFS\" and click next.

    Enter the ADFS server information and User and Group details and click Finish.

    For additional information on configuring ADFS for use with vCenter refer to the vSphere documentation.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000148'
  tag satisfies: ['SRG-APP-000153', 'SRG-APP-000163', 'SRG-APP-000180', 'SRG-APP-000234']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000059'
  tag cci: ['CCI-000764', 'CCI-000770', 'CCI-000795', 'CCI-000804', 'CCI-001682']
  tag nist: ['AC-2 (2)', 'IA-2', 'IA-2 (5)', 'IA-4 e', 'IA-8']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
