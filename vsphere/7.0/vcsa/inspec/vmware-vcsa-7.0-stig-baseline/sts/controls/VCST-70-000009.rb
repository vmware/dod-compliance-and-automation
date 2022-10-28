control 'VCST-70-000009' do
  title 'The Security Token Service must only run one webapp.'
  desc  'VMware ships the Security Token Service on the VCSA with one webapp, in ROOT.war. Any other .war file is potentially malicious and must be removed.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # ls /usr/lib/vmware-sso/vmware-sts/webapps/*.war

    Expected result:

    /usr/lib/vmware-sso/vmware-sts/webapps/ROOT.war

    If the result of this command does not match the expected result, this is a finding.
  "
  desc  'fix', "
    For each unexpected file returned in the check, run the following command:

    # rm /usr/lib/vmware-sso/vmware-sts/webapps/<NAME>.war

    Restart the service with the following command:

    # vmon-cli --restart sts
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag satisfies: ['SRG-APP-000141-WSR-000075']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000009'
  tag cci: ['CCI-000381', 'CCI-001749']
  tag nist: ['CM-5 (3)', 'CM-7 a']

  describe command("ls -A '#{input('appPath')}'/*.war") do
    its('stdout.strip') { should eq '/usr/lib/vmware-sso/vmware-sts/webapps/ROOT.war' }
  end
end
