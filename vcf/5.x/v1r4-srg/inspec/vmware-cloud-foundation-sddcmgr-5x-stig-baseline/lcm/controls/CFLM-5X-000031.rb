control 'CFLM-5X-000031' do
  title 'The SDDC Manager LCM service must offload logs to a centralized logging server.'
  desc  'Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up log records to a different system or onto separate media from the system the application server is actually running on helps to assure that in the event of a catastrophic system failure, the log records will be retained.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep -v \"^#\" /etc/rsyslog.d/stig-services-lcm.conf

    Expected result:

    module(load=\"imfile\" mode=\"inotify\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/lcm/*.log\"
          Tag=\"vcf-lcm-runtime\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/lcm/lcm.out\"
          Tag=\"vcf-lcm-out\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/lcm/thirdparty/upgrades/*/*/upgrade/*.log\"
          Tag=\"vcf-lcm-thirdparty-upgrades-upgrade\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/lcm/thirdparty/upgrades/*/*/logs/*.log\"
          Tag=\"vcf-lcm-thirdparty-upgrades-logs\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/lcm/tools/*.log\"
          Tag=\"vcf-lcm-tools\"
          Severity=\"info\"
          Facility=\"local0\")
    # Adding CAP engine logs here since LCM initiates updates and hands off
    input(type=\"imfile\"
          File=\"/var/log/vmware/capengine/*.log\"
          Tag=\"vcf-cap-engine\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/capengine/cap-update/workflow.log\"
          Tag=\"vcf-cap-engine-update\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/capengine/cap-update-cleanup/workflow.log\"
          Tag=\"vcf-cap-engine-update-cleanup\"
          Severity=\"info\"
          Facility=\"local0\")

    If the file does not exist, this is a finding.

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/rsyslog.d/stig-services-lcm.conf

    Create the file if it does not exist.

    Update the contents of the file as follows:

    module(load=\"imfile\" mode=\"inotify\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/lcm/*.log\"
          Tag=\"vcf-lcm-runtime\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/lcm/lcm.out\"
          Tag=\"vcf-lcm-out\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/lcm/thirdparty/upgrades/*/*/upgrade/*.log\"
          Tag=\"vcf-lcm-thirdparty-upgrades-upgrade\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/lcm/thirdparty/upgrades/*/*/logs/*.log\"
          Tag=\"vcf-lcm-thirdparty-upgrades-logs\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/lcm/tools/*.log\"
          Tag=\"vcf-lcm-tools\"
          Severity=\"info\"
          Facility=\"local0\")
    # Adding CAP engine logs here since LCM initiates updates and hands off
    input(type=\"imfile\"
          File=\"/var/log/vmware/capengine/*.log\"
          Tag=\"vcf-cap-engine\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/capengine/cap-update/workflow.log\"
          Tag=\"vcf-cap-engine-update\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/capengine/cap-update-cleanup/workflow.log\"
          Tag=\"vcf-cap-engine-update-cleanup\"
          Severity=\"info\"
          Facility=\"local0\")

    At the command prompt, run the following command:

    # systemctl restart rsyslog.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000125-AS-000084'
  tag satisfies: ['SRG-APP-000126-AS-000085', 'SRG-APP-000181-AS-000255', 'SRG-APP-000358-AS-000064', 'SRG-APP-000515-AS-000203']
  tag gid: 'V-CFLM-5X-000031'
  tag rid: 'SV-CFLM-5X-000031'
  tag stig_id: 'CFLM-5X-000031'
  tag cci: ['CCI-001348', 'CCI-001350', 'CCI-001851', 'CCI-001876']
  tag nist: ['AU-4 (1)', 'AU-7 a', 'AU-9 (2)', 'AU-9 (3)']

  goodcontent = inspec.profile.file('stig-services-lcm.conf')
  describe file('/etc/rsyslog.d/stig-services-lcm.conf') do
    its('content') { should eq goodcontent }
  end
end
