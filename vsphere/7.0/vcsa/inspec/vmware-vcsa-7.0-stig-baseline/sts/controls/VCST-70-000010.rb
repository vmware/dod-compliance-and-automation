# encoding: UTF-8

control 'VCST-70-000010' do
  title 'The Security Token Service must not be configured with unused realms.'
  desc  "The \"package.access\" entry in the catalina.properties file
implements access control at the package level. When properly configured, a
Security Exception will be reported should an errant or malicious webapp
attempt to access the listed internal classes directly, or if a new class is
defined under the protected packages.

    The Security Token Service comes pre-configured with the appropriate
packages defined in \"package.access\" and this configuration must be
maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep UserDatabaseRealm /usr/lib/vmware-sso/vmware-sts/conf/server.xml

    If the command produces any output, this is a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/server.xml

    Remove the <Realm> node returned in the check.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000010'
  tag fix_id: nil
  tag cci: 'CCI-000381'
  tag nist: ['CM-7 a']

  describe command("grep UserDatabaseRealm '#{input('serverXmlPath')}'") do
    its ('stdout.strip') { should eq '' }
  end

end

