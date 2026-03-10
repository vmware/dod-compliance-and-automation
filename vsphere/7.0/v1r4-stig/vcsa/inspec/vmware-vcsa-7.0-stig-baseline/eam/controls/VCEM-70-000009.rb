control 'VCEM-70-000009' do
  title 'ESX Agent Manager must only run one webapp.'
  desc 'VMware ships ESX Agent Managers on the vCenter Server Appliance (VCSA) with one webapp. Any other path is potentially malicious and must be removed.

'
  desc 'check', 'At the command prompt, run the following command:

# ls -A /usr/lib/vmware-eam/web/webapps

Expected result:

eam

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'For each unexpected directory returned in the check, run the following command:

# rm /usr/lib/vmware-eam/web/webapps/<NAME>

Restart the service with the following command:

# vmon-cli --restart eam'
  impact 0.5
  tag check_id: 'C-60356r888597_chk'
  tag severity: 'medium'
  tag gid: 'V-256681'
  tag rid: 'SV-256681r888599_rule'
  tag stig_id: 'VCEM-70-000009'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag fix_id: 'F-60299r888598_fix'
  tag satisfies: ['SRG-APP-000131-WSR-000073', 'SRG-APP-000141-WSR-000075']
  tag cci: ['CCI-000381', 'CCI-001749']
  tag nist: ['CM-7 a', 'CM-5 (3)']

  describe command("ls -A '#{input('appPath')}'") do
    its('stdout.strip') { should eq 'eam' }
  end
end
