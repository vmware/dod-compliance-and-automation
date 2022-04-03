control 'VCPF-67-000027' do
  title "Rsyslog must be configured to monitor and ship Performance Charts log
files."
  desc  "Performance Charts produces a handful of logs that must be offloaded
from the originating system. This information can then be used for diagnostic
purposes, forensics purposes, or other purposes relevant to ensuring the
availability and integrity of the hosted application.


  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep -v \"^#\" /etc/vmware-syslog/stig-services-perfcharts.conf

    Expected result:

    input(type=\"imfile\"
          File=\"/var/log/vmware/perfcharts/localhost_access_log.*.txt\"
          Tag=\"perfcharts-localhost_access\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/perfcharts/vmware-perfcharts-runtime.log.std*\"
          Tag=\"perfcharts-runtime\"
          Severity=\"info\"
          Facility=\"local0\")

    If the file does not exist, this is a finding.

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc 'fix', "
    Navigate to and open /etc/vmware-syslog/stig-services-perfcharts.conf.

    Create the file if it does not exist.

    Set the contents of the file as follows:

    input(type=\"imfile\"
          File=\"/var/log/vmware/perfcharts/localhost_access_log.*.txt\"
          Tag=\"perfcharts-localhost_access\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/perfcharts/vmware-perfcharts-runtime.log.std*\"
          Tag=\"perfcharts-runtime\"
          Severity=\"info\"
          Facility=\"local0\")
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358-WSR-000163'
  tag satisfies: ['SRG-APP-000358-WSR-000163', 'SRG-APP-000125-WSR-000071']
  tag gid: 'V-239428'
  tag rid: 'SV-239428r675007_rule'
  tag stig_id: 'VCPF-67-000027'
  tag fix_id: 'F-42620r675006_fix'
  tag cci: ['CCI-001348', 'CCI-001851']
  tag nist: ['AU-9 (2)', 'AU-4 (1)']

  describe file('/etc/vmware-syslog/stig-services-perfcharts.conf') do
    it { should exist }
  end
  describe command('grep -v "^#" /etc/vmware-syslog/stig-services-perfcharts.conf') do
    its('stdout') { should match "input(type=\"imfile\"\n      File=\"/var/log/vmware/perfcharts/localhost_access_log.*.txt\"\n      Tag=\"perfcharts-localhost_access\"\n      Severity=\"info\"\n      Facility=\"local0\")\ninput(type=\"imfile\"\n      File=\"/var/log/vmware/perfcharts/vmware-perfcharts-runtime.log.std*\"\n      Tag=\"perfcharts-runtime\"\n      Severity=\"info\"\n      Facility=\"local0\")\n" }
  end
end
