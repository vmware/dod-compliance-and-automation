control 'VRAA-8X-000002' do
  title 'VMware Aria Automation must protect log tools from unauthorized access.'
  desc  "
    Protecting log data also includes identifying and protecting the tools used to view and manipulate log data.

    Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data.

    It is therefore imperative that access to log tools be controlled and protected from unauthorized access.

    Application servers generally provide web- and/or command line-based functionality for managing the application server log capabilities. In addition, subsets of log tool components may be stored on the file system as jar or xml configuration files. The application server must ensure that in addition to protecting any web-based log tools, any file system-based tools are protected as well.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # stat -c \"%a:%U:%G\" /usr/local/bin/vracli

    Expected result:

    700:root:root

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command(s):

    #  chmod 700 /usr/local/bin/vracli
    #  chown root:root /usr/local/bin/vracli
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000121-AS-000081'
  tag satisfies: ['SRG-APP-000122-AS-000082', 'SRG-APP-000123-AS-000083', 'SRG-APP-000340-AS-000185']
  tag gid: 'V-VRAA-8X-000002'
  tag rid: 'SV-VRAA-8X-000002'
  tag stig_id: 'VRAA-8X-000002'
  tag cci: ['CCI-001493', 'CCI-001494', 'CCI-001495', 'CCI-002235']
  tag nist: ['AC-6 (10)', 'AU-9']

  describe file('/usr/local/bin/vracli') do
    it { should_not be_more_permissive_than('0700') }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end
