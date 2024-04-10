control 'VRPE-8X-000008' do
  title 'The VMware Aria Operations Apache server must disable Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs.'
  desc  "Users must not be allowed to access shell programs. Shell programs might run shell escapes and could then perform unauthorized activities that could damage the security posture of the web server. A shell is a program that serves as the basic interface between the user and the operating system. In this regard there are shells that are security risks in the context of a web server and shells that are unauthorized in the context of the Security Features User's Guide."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep -E 'Action|AddHandler' /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | grep -v '^#'

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Remove the lines returned in the check.

    Save and close.

    At the command prompt, run the following command:

    # systemctl restart httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000081'
  tag satisfies: ['SRG-APP-000141-WSR-000083']
  tag gid: 'V-VRPE-8X-000008'
  tag rid: 'SV-VRPE-8X-000008'
  tag stig_id: 'VRPE-8X-000008'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe apache_conf(input('apacheConfPath')) do
    its('Action') { should eq nil }
    its('AddHandler') { should eq nil }
  end
end
