control 'VCRP-70-000008' do
  title 'Envoy log files must be shipped via syslog to a central log server.'
  desc 'Envoy rsyslog configuration is included in the "VMware-visl-integration" package and unpacked to "/etc/vmware-syslog/vmware-services-envoy.conf". Ensuring the package hashes are as expected also ensures the shipped rsyslog configuration is present and unmodified.'
  desc 'check', 'At the command prompt, run the following command:

# rpm -V VMware-visl-integration|grep vmware-services-envoy.conf|grep "^..5......"

If the command returns any output, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/vmware-syslog/vmware-services-envoy.conf

Create the file if it does not exist.

Set the contents of the file as follows:

#envoy service log
input(type="imfile"
      File="/var/log/vmware/envoy/envoy.log"
      Tag="envoy-main"
      Severity="info"
      Facility="local0")
#envoy access log
input(type="imfile"
      File="/var/log/vmware/envoy/envoy-access.log"
      Tag="envoy-access"
      Severity="info"
      Facility="local0")'
  impact 0.5
  tag check_id: 'C-60419r889168_chk'
  tag severity: 'medium'
  tag gid: 'V-256744'
  tag rid: 'SV-256744r889170_rule'
  tag stig_id: 'VCRP-70-000008'
  tag gtitle: 'SRG-APP-000358-WSR-000063'
  tag fix_id: 'F-60362r889169_fix'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  describe command('rpm -V VMware-visl-integration|grep vmware-services-envoy.conf|grep "^..5......"') do
    its('stdout.strip') { should eq '' }
  end
end
