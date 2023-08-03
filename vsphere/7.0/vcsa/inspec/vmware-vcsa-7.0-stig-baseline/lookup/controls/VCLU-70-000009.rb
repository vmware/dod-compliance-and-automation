control 'VCLU-70-000009' do
  title 'Lookup Service must only run one webapp.'
  desc 'VMware ships Lookup Service on the vCenter Server Appliance (VCSA) with one webapp. Any other path is potentially malicious and must be removed.'
  desc 'check', 'At the command prompt, run the following command:

# ls -A /usr/lib/vmware-lookupsvc/webapps/*.war

Expected result:

/usr/lib/vmware-lookupsvc/webapps/ROOT.war

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'For each unexpected directory returned in the check, run the following command:

# rm /usr/lib/vmware-lookupsvc/webapps/<NAME>

Restart the service with the following command:

# vmon-cli --restart lookupsvc'
  impact 0.5
  tag check_id: 'C-60389r888731_chk'
  tag severity: 'medium'
  tag gid: 'V-256714'
  tag rid: 'SV-256714r888733_rule'
  tag stig_id: 'VCLU-70-000009'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag fix_id: 'F-60332r888732_fix'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe command("ls -A '#{input('appPath')}'/*.war") do
    its('stdout.strip') { should eq '/usr/lib/vmware-lookupsvc/webapps/ROOT.war' }
  end
end
