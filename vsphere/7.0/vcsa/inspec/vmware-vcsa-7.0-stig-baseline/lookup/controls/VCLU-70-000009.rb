control 'VCLU-70-000009' do
  title 'Lookup Service must only run one webapp.'
  desc  'VMware ships Lookup Service on the VCSA with one webapp. Any other path is potentially malicious and must be removed.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # ls -A /usr/lib/vmware-lookupsvc/webapps/*.war

    Expected result:

    /usr/lib/vmware-lookupsvc/webapps/ROOT.war

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    For each unexpected directory returned in the check, run the following command:

    # rm /usr/lib/vmware-lookupsvc/webapps/<NAME>

    Restart the service with the following command:

    # vmon-cli --restart lookupsvc
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLU-70-000009'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe command("ls -A '#{input('appPath')}'/*.war") do
    its('stdout.strip') { should eq '/usr/lib/vmware-lookupsvc/webapps/ROOT.war' }
  end
end
