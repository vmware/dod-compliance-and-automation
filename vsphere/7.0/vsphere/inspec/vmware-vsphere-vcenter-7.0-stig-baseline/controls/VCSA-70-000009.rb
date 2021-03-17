# encoding: UTF-8

control 'VCSA-70-000009' do
  title 'The vCenter Server must implement Active Directory authentication.'
  desc  "The vCenter Server must ensure users are authenticated with an
individual authenticator prior to using a group authenticator.  Using Active
Directory for authentication provides more robust account management
capabilities."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Web Client go to Administration >> Single Sign On >>
Configuration >> Identity Provider >> Identity Sources.

    If there is no identity source of type \"Active Directory\" (either Windows
Integrated Authentication or LDAP), this is a finding.

    If a federated identity provider is configured, this is not applicable.
  "
  desc  'fix', "
    From the vSphere Web Client go to Administration >> Single Sign On >>
Configuration >> Identity Provider >> Identity Sources. Click \"Add\".

    Select either \"Active Directory over LDAP\" or \"Active Directory (Windows
Integrated Authentication)\" and configure appropriately.

    Note: Windows Integrated Authentication requires that the vCenter server be
joined to AD via Administration >> Single Sign On >> Configuration >> Identity
Provider >> Active Directory Domain, before configuration.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000153'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000009'
  tag fix_id: nil
  tag cci: 'CCI-000770'
  tag nist: ['IA-2 (5)']

  describe "This check is a manual or policy based check" do
    skip "This must be reviewed manually"
  end

end

