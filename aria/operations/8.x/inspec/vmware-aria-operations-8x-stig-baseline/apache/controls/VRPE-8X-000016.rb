control 'VRPE-8X-000016' do
  title 'The vRealize Operations Manager Apache server must limit the character set used for data entry.'
  desc  "
    Invalid user input occurs when a user inserts data or characters into a hosted application's data entry field and the hosted application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

    An attacker can also enter Unicode characters into hosted applications in an effort to break out of the document home or root home directory or to bypass security checks.

    The web server, by defining the character set available for data entry, can trap efforts to bypass security checks or to compromise an application.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep AddDefaultCharset /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | grep -v '^#'

    Expected result:

    AddDefaultCharset utf-8

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Add or configure the following line:

    AddDefaultCharset utf-8

    Save and close.

    At the command prompt, run the following command:

    # systemctl restart httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000251-WSR-000157'
  tag gid: 'V-VRPE-8X-000016'
  tag rid: 'SV-VRPE-8X-000016'
  tag stig_id: 'VRPE-8X-000016'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']

  describe apache_conf(input('apacheConfPath')) do
    its('AddDefaultCharset') { should cmp 'utf-8' }
  end
end
