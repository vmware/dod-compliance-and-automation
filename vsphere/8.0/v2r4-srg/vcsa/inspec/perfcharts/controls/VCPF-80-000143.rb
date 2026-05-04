control 'VCPF-80-000143' do
  title 'The vCenter Perfcharts service default documentation must be removed.'
  desc  'Tomcat provides documentation and other directories in the default installation that do not serve a production use. These files must be deleted.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # ls -l /usr/lib/vmware-perfcharts/tc-instance/webapps/docs

    If the \"docs\" folder exists or contains any content, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command:

    # rm -rf /usr/lib/vmware-perfcharts/tc-instance/webapps/docs
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VCPF-80-000143'
  tag rid: 'SV-VCPF-80-000143'
  tag stig_id: 'VCPF-80-000143'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Make sure the docs directory does not exist
  describe directory("#{input('appPath')}/webapps/docs").exist? do
    it { should cmp 'false' }
  end
end
