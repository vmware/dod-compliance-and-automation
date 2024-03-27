control 'CFSS-5X-000031' do
  title 'The SDDC Manager SOS service must offload logs to a centralized logging server.'
  desc  'Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up log records to a different system or onto separate media from the system the application server is actually running on helps to assure that in the event of a catastrophic system failure, the log records will be retained.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep -v \"^#\" /etc/rsyslog.d/stig-services-sos.conf

    Expected result:

    module(load=\"imfile\" mode=\"inotify\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/sddc-support/*.log\"
          Tag=\"vcf-sos-logs\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/sddc-support/*/*.log\"
          Tag=\"vcf-sos-bundle-logs\"
          Severity=\"info\"
          Facility=\"local0\")

    If the file does not exist, this is a finding.

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/rsyslog.d/stig-services-sos.conf

    Create the file if it does not exist.

    Set the contents of the file as follows:

    module(load=\"imfile\" mode=\"inotify\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/sddc-support/*.log\"
          Tag=\"vcf-sos-logs\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/sddc-support/*/*.log\"
          Tag=\"vcf-sos-bundle-logs\"
          Severity=\"info\"
          Facility=\"local0\")

    At the command prompt, run the following command:

    # systemctl restart rsyslog.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000125-AS-000084'
  tag satisfies: ['SRG-APP-000126-AS-000085', 'SRG-APP-000181-AS-000255', 'SRG-APP-000358-AS-000064', 'SRG-APP-000515-AS-000203']
  tag gid: 'V-CFSS-5X-000031'
  tag rid: 'SV-CFSS-5X-000031'
  tag stig_id: 'CFSS-5X-000031'
  tag cci: ['CCI-001348', 'CCI-001350', 'CCI-001851', 'CCI-001876']
  tag nist: ['AU-4 (1)', 'AU-7 a', 'AU-9 (2)', 'AU-9 (3)']

  goodcontent = inspec.profile.file('stig-services-sos.conf')
  describe file('/etc/rsyslog.d/stig-services-sos.conf') do
    its('content') { should eq goodcontent }
  end
end
