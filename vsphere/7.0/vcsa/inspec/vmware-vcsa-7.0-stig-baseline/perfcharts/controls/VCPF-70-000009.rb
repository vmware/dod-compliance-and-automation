control 'VCPF-70-000009' do
  title 'Performance Charts must only run one webapp.'
  desc 'VMware ships Performance Charts on the vCenter Server Appliance (VCSA)with one webapp. Any other path is potentially malicious and must be removed.'
  desc 'check', 'At the command prompt, run the following command:

# ls -A /usr/lib/vmware-perfcharts/tc-instance/webapps

Expected result:

statsreport

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'For each unexpected directory returned in the check, run the following command:

# rm /usr/lib/vmware-perfcharts/tc-instance/webapps/<NAME>

Restart the service with the following command:

# vmon-cli --restart perfcharts'
  impact 0.5
  tag check_id: 'C-60294r888346_chk'
  tag severity: 'medium'
  tag gid: 'V-256619'
  tag rid: 'SV-256619r888348_rule'
  tag stig_id: 'VCPF-70-000009'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag fix_id: 'F-60237r888347_fix'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe command("ls -A '#{input('appPath')}'") do
    its('stdout.strip') { should eq 'statsreport' }
  end
end
