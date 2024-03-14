control 'CFNG-5X-000017' do
  title 'The SDDC Manager NGINX service logs must be forwarded to a syslog server.'
  desc  "
    Reviewing log data allows an investigator to recreate the path of an attacker and to capture forensic data for later use. Log data is also essential to system administrators in their daily administrative duties on the hosted system or within the hosted applications.

    If the logging system begins to fail, events will not be recorded. Organizations shall define logging failure events, at which time the application or the logging mechanism the application utilizes will provide a warning to the ISSO and SA at a minimum.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep -v \"^#\" /etc/rsyslog.d/stig-services-nginx.conf

    Expected result:

    input(type=\"imfile\"
          File=\"/var/log/nginx/error.log\"
          Tag=\"nginx-error\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/nginx/access.log\"
          Tag=\"nginx-access\"
          Severity=\"info\"
          Facility=\"local0\")

    If the file does not exist, this is a finding.

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/rsyslog.d/stig-services-nginx.conf

    Create the file if it does not exist.

    Set the contents of the file as follows:

    input(type=\"imfile\"
          File=\"/var/log/nginx/error.log\"
          Tag=\"nginx-error\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/nginx/access.log\"
          Tag=\"nginx-access\"
          Severity=\"info\"
          Facility=\"local0\")

    At the command prompt, run the following command:

    # systemctl restart rsyslog.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000108-WSR-000166'
  tag satisfies: ['SRG-APP-000125-WSR-000071', 'SRG-APP-000358-WSR-000063', 'SRG-APP-000358-WSR-000163']
  tag gid: 'V-CFNG-5X-000017'
  tag rid: 'SV-CFNG-5X-000017'
  tag stig_id: 'CFNG-5X-000017'
  tag cci: ['CCI-000139', 'CCI-001348', 'CCI-001851']
  tag nist: ['AU-4 (1)', 'AU-5 a', 'AU-9 (2)']

  goodcontent = inspec.profile.file('stig-services-nginx.conf')
  describe file('/etc/rsyslog.d/stig-services-nginx.conf') do
    its('content') { should eq goodcontent }
  end
end
