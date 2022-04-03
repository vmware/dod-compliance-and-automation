control 'VCEM-67-000009' do
  title 'ESX Agent Manager must only run one webapp.'
  desc  "VMware ships ESX Agent Managers on the VCSA with one webapp. Any other
path is potentially malicious and must be removed."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # ls -A /usr/lib/vmware-eam/web/webapps

    Expected result:

    eam

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    For each unexpected directory returned in the check, run the following
command:

    # rm /usr/lib/vmware-eam/web/webapps/<NAME>

    Restart the service with the following command:

    # vmon-cli --restart eam
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag gid: 'V-239380'
  tag rid: 'SV-239380r674634_rule'
  tag stig_id: 'VCEM-67-000009'
  tag fix_id: 'F-42572r674633_fix'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe command("ls -A '#{input('appPath')}'") do
    its('stdout.strip') { should eq 'eam' }
  end
end
