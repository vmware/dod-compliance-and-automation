control 'VCEM-70-000029' do
  title 'Rsyslog must be configured to monitor and ship ESX Agent Manager log files.'
  desc  'ESX Agent Manager a number of logs that must be offloaded from the originating system. This information can then be used for diagnostic, forensics, or other purposes relevant to ensuring the availability and integrity of the hosted application.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # rpm -V VMware-visl-integration|grep vmware-services-eam.conf|grep \"^..5......\"

    If the command returns any output, this is a finding.
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
  tag gtitle: 'SRG-APP-000358-WSR-000163'
  tag satisfies: ['SRG-APP-000125-WSR-000071']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCEM-70-000029'
  tag cci: ['CCI-001348', 'CCI-001851']
  tag nist: ['AU-4 (1)', 'AU-9 (2)']

  describe command('rpm -V VMware-visl-integration|grep vmware-services-eam.conf|grep "^..5......"') do
    its('stdout.strip') { should eq '' }
  end
end
