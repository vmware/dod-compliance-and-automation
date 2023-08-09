control 'VCPF-70-000030' do
  title 'Rsyslog must be configured to monitor and ship Performance Charts log files.'
  desc 'Performance Charts produces several logs that must be offloaded from the originating system. This information can then be used for diagnostic purposes, forensics purposes, or other purposes relevant to ensuring the availability and integrity of the hosted application.

'
  desc 'check', 'At the command prompt, run the following command:

# rpm -V VMware-visl-integration|grep vmware-services-perfcharts.conf|grep "^..5......"

If the command returns any output, this is a finding.'
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
      Facility="local0")'
  impact 0.5
  tag check_id: 'C-60315r888409_chk'
  tag severity: 'medium'
  tag gid: 'V-256640'
  tag rid: 'SV-256640r888411_rule'
  tag stig_id: 'VCPF-70-000030'
  tag gtitle: 'SRG-APP-000358-WSR-000163'
  tag fix_id: 'F-60258r888410_fix'
  tag satisfies: ['SRG-APP-000358-WSR-000163', 'SRG-APP-000125-WSR-000071']
  tag cci: ['CCI-001348', 'CCI-001851']
  tag nist: ['AU-9 (2)', 'AU-4 (1)']

  describe command('rpm -V VMware-visl-integration|grep vmware-services-perfcharts.conf|grep "^..5......"') do
    its('stdout.strip') { should eq '' }
  end
end
