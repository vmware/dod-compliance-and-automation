control 'VCPF-70-000030' do
  title 'Rsyslog must be configured to monitor and ship Performance Charts log files.'
  desc  'The Performance Charts produces a handful of logs that must be offloaded from the originating system. This information can then be used for diagnostic purposes, forensics purposes, or other purposes relevant to ensuring the availability and integrity of the hosted application.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # rpm -V VMware-visl-integration|grep vmware-services-perfcharts.conf|grep \"^..5......\"

    If the command returns any output, this is a finding.
  "
  desc 'fix', "
    Navigate to and open

    /etc/vmware-syslog/vmware-services-perfcharts.conf

    Create the file if it does not exist.

    Set the contents of the file as follows:

    #stats
    input(type=\"imfile\"
          File=\"/var/log/vmware/perfcharts/stats.log\"
          Tag=\"perfcharts-stats\"
          Severity=\"info\"
          Facility=\"local0\")
    #localhost_access_log
    input(type=\"imfile\"
          File=\"/var/log/vmware/perfcharts/localhost_access_log.txt\"
          Tag=\"perfcharts-localhost_access\"
          Severity=\"info\"
          Facility=\"local0\")
    #vmware-perfcharts-gc.log
    input(type=\"imfile\"
          File=\"/var/log/vmware/perfcharts/vmware-perfcharts-gc.log.*.current\"
          Tag=\"perfcharts-gc\"
          Severity=\"info\"
          Facility=\"local0\")
    #vmware-perfcharts-runtime.log
    input(type=\"imfile\"
          File=\"/var/log/vmware/perfcharts/vmware-perfcharts-runtime.log.std*\"
          Tag=\"perfcharts-runtime\"
          Severity=\"info\"
          Facility=\"local0\")
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358-WSR-000163'
  tag satisfies: ['SRG-APP-000125-WSR-000071']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCPF-70-000030'
  tag cci: ['CCI-001348', 'CCI-001851']
  tag nist: ['AU-4 (1)', 'AU-9 (2)']

  describe command('rpm -V VMware-visl-integration|grep vmware-services-perfcharts.conf|grep "^..5......"') do
    its('stdout.strip') { should eq '' }
  end
end
