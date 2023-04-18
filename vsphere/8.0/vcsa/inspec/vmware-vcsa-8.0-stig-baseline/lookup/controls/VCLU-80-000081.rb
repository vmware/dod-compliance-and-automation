control 'VCLU-80-000081' do
  title 'The vCenter Lookup service must offload log records onto a different system or media from the system being logged.'
  desc  "
    Information system logging capability is critical for accurate forensic analysis. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, filenames involved, and access control or flow control rules invoked.

    Offloading is a common process in information systems with limited log storage capacity.

    Centralized management of log records provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Application servers and their related components are required to offload log records onto a different system or media than the system being logged.
  "
  desc  'rationale', ''
  desc  'check', "
    By default, a vmware-services-lookupsvc.conf rsyslog configuration file that includes the service logs when syslog is configured on vCenter, but it must be verified.

    At the command prompt, run the following command:

    # cat /etc/vmware-syslog/vmware-services-lookupsvc.conf

    Expected result:

    #catalina
    input(type=\"imfile\"
          File=\"/var/log/vmware/lookupsvc/tomcat/catalina.*.log\"
          Tag=\"lookupsvc-tc-catalina\"
          Severity=\"info\"
          Facility=\"local0\")
    #localhost
    input(type=\"imfile\"
          File=\"/var/log/vmware/lookupsvc/tomcat/localhost.*.log\"
          Tag=\"lookupsvc-tc-localhost\"
          Severity=\"info\"
          Facility=\"local0\")
    #localhost_access_log
    input(type=\"imfile\"
          File=\"/var/log/vmware/lookupsvc/tomcat/localhost_access.log\"
          Tag=\"lookupsvc-localhost_access\"
          Severity=\"info\"
          Facility=\"local0\")
    #lookupsvc-init
    input(type=\"imfile\"
          File=\"/var/log/vmware/lookupsvc/lookupsvc-init.log\"
          Tag=\"lookupsvc-init\"
          Severity=\"info\"
          Facility=\"local0\")
    #prestart
    input(type=\"imfile\"
          File=\"/var/log/vmware/lookupsvc/prestart.log\"
          Tag=\"lookupsvc-prestart\"
          Severity=\"info\"
          Facility=\"local0\")
    #lookupserver-default
    input(type=\"imfile\"
          File=\"/var/log/vmware/lookupsvc/lookupserver-default.log\"
          Tag=\"lookupsvc-lookupserver-default\"
          Severity=\"info\"
          Facility=\"local0\")
    #lookupsvc_stream.log.std
    input(type=\"imfile\"
          File=\"/var/log/vmware/lookupsvc/lookupsvc_stream.log.std*\"
          Tag=\"lookupsvc-std\"
          Severity=\"info\"
          Facility=\"local0\")
    #ls-gc
    input(type=\"imfile\"
          File=\"/var/log/vmware/lookupsvc/vmware-lookupsvc-gc.log.*.current\"
          Tag=\"lookupsvc-gc\"
          Severity=\"info\"
          Facility=\"local0\")

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/vmware-syslog/vmware-services-lookupsvc.conf

    Create the file if it does not exist.

    Set the contents of the file as follows:

    #catalina
    input(type=\"imfile\"
          File=\"/var/log/vmware/lookupsvc/tomcat/catalina.*.log\"
          Tag=\"lookupsvc-tc-catalina\"
          Severity=\"info\"
          Facility=\"local0\")
    #localhost
    input(type=\"imfile\"
          File=\"/var/log/vmware/lookupsvc/tomcat/localhost.*.log\"
          Tag=\"lookupsvc-tc-localhost\"
          Severity=\"info\"
          Facility=\"local0\")
    #localhost_access_log
    input(type=\"imfile\"
          File=\"/var/log/vmware/lookupsvc/tomcat/localhost_access.log\"
          Tag=\"lookupsvc-localhost_access\"
          Severity=\"info\"
          Facility=\"local0\")
    #lookupsvc-init
    input(type=\"imfile\"
          File=\"/var/log/vmware/lookupsvc/lookupsvc-init.log\"
          Tag=\"lookupsvc-init\"
          Severity=\"info\"
          Facility=\"local0\")
    #prestart
    input(type=\"imfile\"
          File=\"/var/log/vmware/lookupsvc/prestart.log\"
          Tag=\"lookupsvc-prestart\"
          Severity=\"info\"
          Facility=\"local0\")
    #lookupserver-default
    input(type=\"imfile\"
          File=\"/var/log/vmware/lookupsvc/lookupserver-default.log\"
          Tag=\"lookupsvc-lookupserver-default\"
          Severity=\"info\"
          Facility=\"local0\")
    #lookupsvc_stream.log.std
    input(type=\"imfile\"
          File=\"/var/log/vmware/lookupsvc/lookupsvc_stream.log.std*\"
          Tag=\"lookupsvc-std\"
          Severity=\"info\"
          Facility=\"local0\")
    #ls-gc
    input(type=\"imfile\"
          File=\"/var/log/vmware/lookupsvc/vmware-lookupsvc-gc.log.*.current\"
          Tag=\"lookupsvc-gc\"
          Severity=\"info\"
          Facility=\"local0\")
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358-AS-000064'
  tag gid: 'V-VCLU-80-000081'
  tag rid: 'SV-VCLU-80-000081'
  tag stig_id: 'VCLU-80-000081'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  goodcontent = inspec.profile.file('vmware-services-lookupsvc.conf')
  describe file('/etc/vmware-syslog/vmware-services-lookupsvc.conf') do
    its('content') { should eq goodcontent }
  end
end
