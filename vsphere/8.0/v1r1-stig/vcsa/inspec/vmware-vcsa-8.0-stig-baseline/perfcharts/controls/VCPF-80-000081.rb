control 'VCPF-80-000081' do
  title 'The vCenter Perfcharts service must offload log records onto a different system or media from the system being logged.'
  desc 'Information system logging capability is critical for accurate forensic analysis. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, filenames involved, and access control or flow control rules invoked.

Offloading is a common process in information systems with limited log storage capacity.

Centralized management of log records provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Application servers and their related components are required to offload log records onto a different system or media than the system being logged.'
  desc 'check', 'By default, a vmware-services-perfcharts.conf rsyslog configuration file includes the service logs when syslog is configured on vCenter, but it must be verified.

At the command prompt, run the following command:

# cat /etc/vmware-syslog/vmware-services-perfcharts.conf

Expected result:

#stats
input(type="imfile"
      File="/var/log/vmware/perfcharts/stats.log"
      Tag="perfcharts-stats"
      Severity="info"
      Facility="local0")
#localhost_access_log
input(type="imfile"
      File="/var/log/vmware/perfcharts/localhost_access_log.txt"
      Tag="perfcharts-localhost_access"
      Severity="info"
      Facility="local0")
#vmware-perfcharts-gc.log
input(type="imfile"
      File="/var/log/vmware/perfcharts/vmware-perfcharts-gc.log.*.current"
      Tag="perfcharts-gc"
      Severity="info"
      Facility="local0")
#vmware-perfcharts-runtime.log
input(type="imfile"
      File="/var/log/vmware/perfcharts/vmware-perfcharts-runtime.log.std*"
      Tag="perfcharts-runtime"
      Severity="info"
      Facility="local0")
#tomcat/catalina_log
input(type="imfile"
      File="/var/log/vmware/perfcharts/tomcat/catalina.*.log"
      Tag="perfcharts-tomcat-catalina"
      Severity="info"
      Facility="local0")
#tomcat/localhost_log
input(type="imfile"
      File="/var/log/vmware/perfcharts/tomcat/localhost.*.log"
      Tag="perfcharts-tomcat-localhost"
      Severity="info"
      Facility="local0")

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/vmware-syslog/vmware-services-perfcharts.conf

Create the file if it does not exist.

Set the contents of the file as follows:

#stats
input(type="imfile"
      File="/var/log/vmware/perfcharts/stats.log"
      Tag="perfcharts-stats"
      Severity="info"
      Facility="local0")
#localhost_access_log
input(type="imfile"
      File="/var/log/vmware/perfcharts/localhost_access_log.txt"
      Tag="perfcharts-localhost_access"
      Severity="info"
      Facility="local0")
#vmware-perfcharts-gc.log
input(type="imfile"
      File="/var/log/vmware/perfcharts/vmware-perfcharts-gc.log.*.current"
      Tag="perfcharts-gc"
      Severity="info"
      Facility="local0")
#vmware-perfcharts-runtime.log
input(type="imfile"
      File="/var/log/vmware/perfcharts/vmware-perfcharts-runtime.log.std*"
      Tag="perfcharts-runtime"
      Severity="info"
      Facility="local0")
#tomcat/catalina_log
input(type="imfile"
      File="/var/log/vmware/perfcharts/tomcat/catalina.*.log"
      Tag="perfcharts-tomcat-catalina"
      Severity="info"
      Facility="local0")
#tomcat/localhost_log
input(type="imfile"
      File="/var/log/vmware/perfcharts/tomcat/localhost.*.log"
      Tag="perfcharts-tomcat-localhost"
      Severity="info"
      Facility="local0")'
  impact 0.5
  tag check_id: 'C-62824r934908_chk'
  tag severity: 'medium'
  tag gid: 'V-259084'
  tag rid: 'SV-259084r934910_rule'
  tag stig_id: 'VCPF-80-000081'
  tag gtitle: 'SRG-APP-000358-AS-000064'
  tag fix_id: 'F-62733r934909_fix'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  goodcontent = inspec.profile.file('vmware-services-perfcharts.conf')
  describe file('/etc/vmware-syslog/vmware-services-perfcharts.conf') do
    its('content') { should eq goodcontent }
  end
end
