control 'VCPF-70-000009' do
  title 'Performance Charts must only run one webapp.'
  desc  'VMware ships Performance Charts on the VCSA with one webapp. Any other path is potentially malicious and must be removed.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # ls -A /usr/lib/vmware-perfcharts/tc-instance/webapps

    Expected result:

    statsreport

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    For each unexpected directory returned in the check, run the following command:

    # rm /usr/lib/vmware-perfcharts/tc-instance/webapps/<NAME>

    Restart the service with the following command:

    # vmon-cli --restart perfcharts
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCPF-70-000009'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe command("ls -A '#{input('appPath')}'") do
    its('stdout.strip') { should eq 'statsreport' }
  end
end
