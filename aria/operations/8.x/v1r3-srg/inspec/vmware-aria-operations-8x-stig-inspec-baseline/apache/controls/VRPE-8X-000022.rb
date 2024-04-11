control 'VRPE-8X-000022' do
  title 'The VMware Aria Operations Apache server must be protected from being stopped by a non-privileged user.'
  desc  "
    An attacker has at least two reasons to stop a web server. The first is to cause a DoS, and the second is to put in place changes the attacker made to the web server configuration.

    To prohibit an attacker from stopping the web server, the process ID (pid) of the web server and the utilities used to start/stop the web server must be protected from access by non-privileged users. By knowing the pid and having access to the web server utilities, a non-privileged user has a greater capability of stopping the server, whether intentionally or unintentionally.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # stat -c %a:%U:%G /usr/lib/systemd/system/httpd.service

    Expected result:

    640:root:root

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command(s):

    # chmod 640 /usr/lib/systemd/system/httpd.service
    # chown root:root /usr/lib/systemd/system/httpd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag gid: 'V-VRPE-8X-000022'
  tag rid: 'SV-VRPE-8X-000022'
  tag stig_id: 'VRPE-8X-000022'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5']

  describe file(input('httpdServiceFile')) do
    it { should_not be_more_permissive_than('0640') }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end
