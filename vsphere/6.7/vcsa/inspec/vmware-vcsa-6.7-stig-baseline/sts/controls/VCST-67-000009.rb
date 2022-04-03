control 'VCST-67-000009' do
  title 'The Security Token Service must only run one web app.'
  desc  "VMware ships the Security Token Service on the VCSA with one web app,
in ROOT.war. Any other .war file is potentially malicious and must be removed."
  desc  'rationale', ''
  desc  'check', "
    Connect to the PSC, whether external or embedded.

    At the command prompt, execute the following command:

    # ls /usr/lib/vmware-sso/vmware-sts/webapps/*.war

    Expected result:

    /usr/lib/vmware-sso/vmware-sts/webapps/ROOT.war

    If the result of this command does not match the expected result, this is a
finding.
  "
  desc 'fix', "
    Connect to the PSC, whether external or embedded.

    For each unexpected file returned in the check, run the following command:

    # rm /usr/lib/vmware-sso/vmware-sts/webapps/<NAME>.war

    Restart the service with the following command:

    # service-control --restart vmware-stsd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag gid: 'V-239660'
  tag rid: 'SV-239660r816705_rule'
  tag stig_id: 'VCST-67-000009'
  tag fix_id: 'F-42852r816704_fix'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe command("ls -A '#{input('appPath')}'/*.war") do
    its('stdout.strip') { should eq '/usr/lib/vmware-sso/vmware-sts/webapps/ROOT.war' }
  end
end
