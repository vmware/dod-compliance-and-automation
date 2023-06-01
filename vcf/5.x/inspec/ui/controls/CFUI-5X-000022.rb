control 'CFUI-5X-000022' do
  title 'The SDDC Manager UI service must offload logs to a centralized logging server.'
  desc  'Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up log records to an unrelated system or onto separate media than the system the web server is actually running on helps to assure that, in the event of a catastrophic system failure, the log records will be retained.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep -v \"^#\" /etc/rsyslog.d/stig-services-sddc-manager-ui-app.conf

    Expected result:

    module(load=\"imfile\" mode=\"inotify\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/sddc-manager-ui-app/access.log\"
          Tag=\"vcf-sddc-manager-ui-app-access\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/sddc-manager-ui-app/cspViolationReport.log\"
          Tag=\"vcf-sddc-manager-ui-app-cspviolations\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/sddc-manager-ui-app/sddcManagerServer.log\"
          Tag=\"vcf-sddc-manager-ui-app-runtime\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/sddc-manager-ui-app/sddc-manager-ui-activity.log\"
          Tag=\"vcf-sddc-manager-ui-app-activity\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/sddc-manager-ui-app/supervisor.log\"
          Tag=\"vcf-sddc-manager-ui-app-supervisor\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/sddc-manager-ui-app/user-logs/*/*.log\"
          Tag=\"vcf-sddc-manager-ui-app-user-logs\"
          Severity=\"info\"
          Facility=\"local0\")

    If the file does not exist, this is a finding.

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/rsyslog.d/stig-services-sddc-manager-ui-app.conf

    Create the file if it does not exist.

    Update the contents of the file as follows:

    module(load=\"imfile\" mode=\"inotify\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/sddc-manager-ui-app/access.log\"
          Tag=\"vcf-sddc-manager-ui-app-access\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/sddc-manager-ui-app/cspViolationReport.log\"
          Tag=\"vcf-sddc-manager-ui-app-cspviolations\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/sddc-manager-ui-app/sddcManagerServer.log\"
          Tag=\"vcf-sddc-manager-ui-app-runtime\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/sddc-manager-ui-app/sddc-manager-ui-activity.log\"
          Tag=\"vcf-sddc-manager-ui-app-activity\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/sddc-manager-ui-app/supervisor.log\"
          Tag=\"vcf-sddc-manager-ui-app-supervisor\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/sddc-manager-ui-app/user-logs/*/*.log\"
          Tag=\"vcf-sddc-manager-ui-app-user-logs\"
          Severity=\"info\"
          Facility=\"local0\")

    At the command prompt, run the following command:

    # systemctl restart rsyslog.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000125-WSR-000071'
  tag satisfies: ['SRG-APP-000358-WSR-000063', 'SRG-APP-000358-WSR-000163']
  tag gid: 'V-CFUI-5X-000022'
  tag rid: 'SV-CFUI-5X-000022'
  tag stig_id: 'CFUI-5X-000022'
  tag cci: ['CCI-001348', 'CCI-001851']
  tag nist: ['AU-4 (1)', 'AU-9 (2)']

  goodcontent = inspec.profile.file('stig-services-sddc-manager-ui-app.conf')
  describe file('/etc/rsyslog.d/stig-services-sddc-manager-ui-app.conf') do
    its('content') { should eq goodcontent }
  end
end
