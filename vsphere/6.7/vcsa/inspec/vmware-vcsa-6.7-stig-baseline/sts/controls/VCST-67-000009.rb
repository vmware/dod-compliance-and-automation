control "VCST-67-000009" do
  title "The Security Token Service must only run one webapp."
  desc  "VMware ships the Security Token Service on the VCSA with one webapp,
in ROOT.war. Any other .war file is potentially malicious and must be removed."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000131-WSR-000073"
  tag gid: nil
  tag rid: "VCST-67-000009"
  tag stig_id: "VCST-67-000009"
  tag cci: "CCI-001749"
  tag nist: ["CM-5 (3)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# ls /usr/lib/vmware-sso/vmware-sts/webapps/*.war

Expected result:

/usr/lib/vmware-sso/vmware-sts/webapps/ROOT.war

If the result of this command does not match the expected result, this is a
finding."
  desc 'fix', "For each unexpected file returned in the check, run the following
command:

# rm /usr/lib/vmware-sso/vmware-sts/webapps/<NAME>.war

Restart the service with the following command:

# service-control --restart vmware-stsd"

  describe command('ls /usr/lib/vmware-sso/vmware-sts/webapps/*.war') do
    its ('stdout.strip') { should eq '/usr/lib/vmware-sso/vmware-sts/webapps/ROOT.war' }
  end

end