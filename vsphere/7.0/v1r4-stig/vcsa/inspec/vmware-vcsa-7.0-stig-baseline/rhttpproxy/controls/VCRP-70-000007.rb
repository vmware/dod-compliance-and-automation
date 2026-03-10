control 'VCRP-70-000007' do
  title 'Envoy (rhttpproxy) log files must be shipped via syslog to a central log server.'
  desc 'Envoy produces several logs that must be offloaded from the originating system. This information can then be used for diagnostic purposes, forensics purposes, or other purposes relevant to ensuring the availability and integrity of the hosted application.

Envoy (rhttpproxy) rsyslog configuration is included in the "VMware-visl-integration" package and unpacked to "/etc/vmware-syslog/vmware-services-rhttpproxy.conf". Ensuring the package hashes are as expected also ensures the shipped rsyslog configuration is present and unmodified.'
  desc 'check', 'At the command prompt, run the following command:

# rpm -V VMware-visl-integration|grep vmware-services-rhttpproxy.conf|grep "^..5......"

If the command returns any output, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/vmware-syslog/vmware-services-rhttpproxy.conf

Create the file if it does not exist.

Set the contents of the file as follows:

#rhttpproxy log
input(type="imfile"
      File="/var/log/vmware/rhttpproxy/rhttpproxy.log"
      Tag="rhttpproxy-main"
      Severity="info"
      Facility="local0")'
  impact 0.5
  tag check_id: 'C-60418r889165_chk'
  tag severity: 'medium'
  tag gid: 'V-256743'
  tag rid: 'SV-256743r889167_rule'
  tag stig_id: 'VCRP-70-000007'
  tag gtitle: 'SRG-APP-000358-WSR-000063'
  tag fix_id: 'F-60361r889166_fix'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  describe command('rpm -V VMware-visl-integration|grep vmware-services-rhttpproxy.conf|grep "^..5......"') do
    its('stdout.strip') { should eq '' }
  end
end
