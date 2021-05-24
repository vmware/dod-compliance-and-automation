# encoding: UTF-8

control 'VCST-70-000009' do
  title 'The Security Token Service must only run one webapp.'
  desc  "The Security Token Service performs user authentication at the
application level and not through Tomcat. To eliminate unnecessary features and
to ensure that the Security Token Service remains in it's shipping state, the
lack of a \"UserDatabaseRealm\" configuration must be confirmed."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # ls /usr/lib/vmware-sso/vmware-sts/webapps/*.war

    Expected result:

    /usr/lib/vmware-sso/vmware-sts/webapps/ROOT.war

    If the result of this command does not match the expected result, this is a
finding.
  "
  desc  'fix', "
    For each unexpected file returned in the check, run the following command:

    # rm /usr/lib/vmware-sso/vmware-sts/webapps/<NAME>.war

    Restart the service with the following command:

    # service-control --restart vmware-stsd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000009'
  tag fix_id: nil
  tag cci: 'CCI-001749'
  tag nist: ['CM-5 (3)']

  describe command("ls -A '#{input('appPath')}'/*.war") do
    its ('stdout.strip') { should eq '/usr/lib/vmware-sso/vmware-sts/webapps/ROOT.war' }
  end

end

