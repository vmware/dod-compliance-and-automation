control 'VCFH-9X-000030' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service must have Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs disabled.'
  desc  "
    Controlling what a user of a hosted application can access is part of the security posture of the web server. Any time a user can access more functionality than is needed for the operation of the hosted application poses a security issue. A user with too much access can view information that is not needed for the user's job role, or the user could use the function in an unintentional manner.

    A MIME tells the web server what type of program various file types and extensions are and what external utilities or programs are needed to execute the file type.

    A shell is a program that serves as the basic interface between the user and the operating system, so hosted application users must not have access to these programs. Shell programs may execute shell escapes and can then perform unauthorized activities that could damage the security posture of the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that no shell file types are enabled.

    At the command prompt, run the following:

    # grep -i -E \"Action|AddHandler\" /etc/httpd/conf/httpd.conf /etc/httpd/conf/extra/httpd-ssl.conf /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    If \"Action\" or \"AddHandler\" exist and they configure .exe, .dll, .com, .bat, or .csh, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/httpd/conf/httpd.conf

    Note: If the offending configuration was found in a different file edit that file instead.

    Remove or comment the target \"Action\" or \"AddHandler\" directive.

    Reload the configuration by running the following command:

    # systemctl reload httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000081'
  tag satisfies: ['SRG-APP-000141-WSR-000083']
  tag gid: 'V-VCFH-9X-000030'
  tag rid: 'SV-VCFH-9X-000030'
  tag stig_id: 'VCFH-9X-000030'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  conf = input('apache_httpd_conf_file')

  # Make sure the conf file exists so the tests do not pass with false positives
  describe file(conf) do
    it { should exist }
  end
  if apache_conf_custom(conf).Action.nil?
    describe 'No Action directive found and' do
      subject { apache_conf_custom(conf).Action }
      it { should be nil }
    end
  else
    describe apache_conf_custom(conf) do
      its('Action') { should_not match /(\.exe|\.dll|\.com|\.bat|\.csh|\.sh)/ }
    end
  end
  if apache_conf_custom(conf).AddHandler.nil?
    describe 'No AddHandler directive found and' do
      subject { apache_conf_custom(conf).AddHandler }
      it { should be nil }
    end
  else
    describe apache_conf_custom(conf) do
      its('AddHandler') { should_not match /(\.exe|\.dll|\.com|\.bat|\.csh|\.sh)/ }
    end
  end
end
