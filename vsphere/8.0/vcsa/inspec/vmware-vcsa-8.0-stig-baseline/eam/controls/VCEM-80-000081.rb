control 'VCEM-80-000081' do
  title 'The vCenter ESX Agent Manager service must offload log records onto a different system or media from the system being logged.'
  desc  "
    Information system logging capability is critical for accurate forensic analysis. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, filenames involved, and access control or flow control rules invoked.

    Offloading is a common process in information systems with limited log storage capacity.

    Centralized management of log records provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Application servers and their related components are required to offload log records onto a different system or media than the system being logged.
  "
  desc  'rationale', ''
  desc  'check', "
    By default, a vmware-services-eam.conf rsyslog configuration file includes the service logs when syslog is configured on vCenter, but it must be verified.

    At the command prompt, run the following command:

    # cat /etc/vmware-syslog/vmware-services-eam.conf

    Expected result:

    #eam.log
    input(type=\"imfile\"
          File=\"/var/log/vmware/eam/eam.log\"
          Tag=\"eam-main\"
          Severity=\"info\"
          Facility=\"local0\")
    #eam_api.log
    input(type=\"imfile\"
          File=\"/var/log/vmware/eam/eam_api.log\"
          Tag=\"eam-api\"
          Severity=\"info\"
          Facility=\"local0\")
    #eam web access logs
    input(type=\"imfile\"
          File=\"/var/log/vmware/eam/web/localhost_access.log\"
          Tag=\"eam-access\"
          Severity=\"info\"
          Facility=\"local0\")
    #eam jvm logs
    input(type=\"imfile\"
          File=\"/var/log/vmware/eam/jvm.log.stdout\"
          Tag=\"eam-stdout\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/eam/jvm.log.stderr\"
          Tag=\"eam-stderr\"
          Severity=\"info\"
          Facility=\"local0\")
    #eam catalina logs
    input(type=\"imfile\"
          File=\"/var/log/vmware/eam/web/catalina.log\"
          Tag=\"eam-catalina\"
          Severity=\"info\"
          Facility=\"local0\")
    #eam catalina localhost logs
    input(type=\"imfile\"
          File=\"/var/log/vmware/eam/web/localhost.log\"
          Tag=\"eam-catalina\"
          Severity=\"info\"
          Facility=\"local0\")
    #eam firstboot logs
    input(type=\"imfile\"
          File=\"/var/log/vmware/firstboot/eam_firstboot.py*.log\"
          Tag=\"eam-firstboot\"
          Severity=\"info\"
          Facility=\"local0\")

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/vmware-syslog/vmware-services-eam.conf

    Create the file if it does not exist.

    Set the contents of the file as follows:

    #eam.log
    input(type=\"imfile\"
          File=\"/var/log/vmware/eam/eam.log\"
          Tag=\"eam-main\"
          Severity=\"info\"
          Facility=\"local0\")
    #eam_api.log
    input(type=\"imfile\"
          File=\"/var/log/vmware/eam/eam_api.log\"
          Tag=\"eam-api\"
          Severity=\"info\"
          Facility=\"local0\")
    #eam web access logs
    input(type=\"imfile\"
          File=\"/var/log/vmware/eam/web/localhost_access.log\"
          Tag=\"eam-access\"
          Severity=\"info\"
          Facility=\"local0\")
    #eam jvm logs
    input(type=\"imfile\"
          File=\"/var/log/vmware/eam/jvm.log.stdout\"
          Tag=\"eam-stdout\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/eam/jvm.log.stderr\"
          Tag=\"eam-stderr\"
          Severity=\"info\"
          Facility=\"local0\")
    #eam catalina logs
    input(type=\"imfile\"
          File=\"/var/log/vmware/eam/web/catalina.log\"
          Tag=\"eam-catalina\"
          Severity=\"info\"
          Facility=\"local0\")
    #eam catalina localhost logs
    input(type=\"imfile\"
          File=\"/var/log/vmware/eam/web/localhost.log\"
          Tag=\"eam-catalina\"
          Severity=\"info\"
          Facility=\"local0\")
    #eam firstboot logs
    input(type=\"imfile\"
          File=\"/var/log/vmware/firstboot/eam_firstboot.py*.log\"
          Tag=\"eam-firstboot\"
          Severity=\"info\"
          Facility=\"local0\")
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358-AS-000064'
  tag gid: 'V-VCEM-80-000081'
  tag rid: 'SV-VCEM-80-000081'
  tag stig_id: 'VCEM-80-000081'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  goodcontent = inspec.profile.file('vmware-services-eam.conf')
  describe file('/etc/vmware-syslog/vmware-services-eam.conf') do
    its('content') { should eq goodcontent }
  end
end
