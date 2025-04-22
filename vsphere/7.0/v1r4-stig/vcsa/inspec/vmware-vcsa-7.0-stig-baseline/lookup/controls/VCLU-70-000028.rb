control 'VCLU-70-000028' do
  title 'Lookup Service log files must be offloaded to a central log server in real time.'
  desc 'Lookup Service produces several logs that must be offloaded from the originating system. This information can then be used for diagnostic, forensics, or other purposes relevant to ensuring the availability and integrity of the hosted application.

'
  desc 'check', 'At the command prompt, run the following command:

# rpm -V VMware-visl-integration|grep vmware-services-lookupsvc.conf

If the above command returns any output, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/vmware-syslog/vmware-services-lookupsvc.conf

Create the file if it does not exist.

Set the contents of the file as follows:

#localhost_access_log
input(type="imfile"
      File="/var/log/vmware/lookupsvc/tomcat/localhost_access.log"
      Tag="lookupsvc-localhost_access"
      Severity="info"
      Facility="local0")
#lookupsvc_stream.log.std
input(type="imfile"
      File="/var/log/vmware/lookupsvc/lookupsvc_stream.log.std*"
      Tag="lookupsvc-std"
      Severity="info"
      Facility="local0")
#lookupserver-default
input(type="imfile"
      File="/var/log/vmware/lookupsvc/lookupserver-default.log"
      Tag="lookupsvc-lookupserver-default"
      Severity="info"
      Facility="local0")
#lookupServer
input(type="imfile"
      File="/var/log/vmware/lookupsvc/lookupServer.log"
      Tag="lookupsvc-lookupServer"
      Severity="info"
      Facility="local0")
#ls-perflogs
input(type="imfile"
      File="/var/log/vmware/lookupsvc/vmware-lookupservice-perf.log"
      Tag="lookupsvc-perf"
      Severity="info"
      Facility="local0")
#ls-gc
input(type="imfile"
      File="/var/log/vmware/lookupsvc/vmware-lookupsvc-gc.log.*.current"
      Tag="lookupsvc-gc"
      Severity="info"
      Facility="local0")'
  impact 0.5
  tag check_id: 'C-60408r888788_chk'
  tag severity: 'medium'
  tag gid: 'V-256733'
  tag rid: 'SV-256733r888790_rule'
  tag stig_id: 'VCLU-70-000028'
  tag gtitle: 'SRG-APP-000358-WSR-000163'
  tag fix_id: 'F-60351r888789_fix'
  tag satisfies: ['SRG-APP-000358-WSR-000163', 'SRG-APP-000108-WSR-000166', 'SRG-APP-000125-WSR-000071']
  tag cci: ['CCI-000139', 'CCI-001348', 'CCI-001851']
  tag nist: ['AU-5 a', 'AU-9 (2)', 'AU-4 (1)']

  describe command('rpm -V VMware-visl-integration|grep vmware-services-lookupsvc.conf|grep "^..5......"') do
    its('stdout.strip') { should eq '' }
  end
end
