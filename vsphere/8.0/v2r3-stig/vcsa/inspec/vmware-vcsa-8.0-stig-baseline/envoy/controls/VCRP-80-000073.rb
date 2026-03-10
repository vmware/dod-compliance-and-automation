control 'VCRP-80-000073' do
  title 'The vCenter Rhttpproxy service log files must be sent to a central log server.'
  desc 'Writing events to a centralized management audit system offers many benefits to the enterprise over having dispersed logs. Centralized management of audit records and logs provides for efficiency in maintenance and management of records, enterprise analysis of events, and backup and archiving of event records enterprise-wide. The web server and related components are required to be capable of writing logs to centralized audit log servers.
'
  desc 'check', 'By default, there is a vmware-services-rhttpproxy.conf rsyslog configuration file that includes the service logs when syslog is configured on vCenter, but it must be verified.

At the command prompt, run the following command:

# cat /etc/vmware-syslog/vmware-services-rhttpproxy.conf

Expected result:

#rhttpproxy log
input(type="imfile"
      File="/var/log/vmware/rhttpproxy/rhttpproxy.log"
      Tag="rhttpproxy-main"
      Severity="info"
      Facility="local0")
#rhttpproxy init stdout
input(type="imfile"
      File="/var/log/vmware/rhttpproxy/rproxy_init.log.stdout"
      Tag="rhttpproxy-stdout"
      Severity="info"
      Facility="local0")
#rhttpproxy init stderr
input(type="imfile"
      File="/var/log/vmware/rhttpproxy/rproxy_init.log.stderr"
      Tag="rhttpproxy-stderr"
      Severity="info"
      Facility="local0")

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/vmware-syslog/vmware-services-rhttpproxy.conf

Create the file if it does not exist.

Set the contents of the file as follows:

#rhttpproxy log
input(type="imfile"
      File="/var/log/vmware/rhttpproxy/rhttpproxy.log"
      Tag="rhttpproxy-main"
      Severity="info"
      Facility="local0")
#rhttpproxy init stdout
input(type="imfile"
      File="/var/log/vmware/rhttpproxy/rproxy_init.log.stdout"
      Tag="rhttpproxy-stdout"
      Severity="info"
      Facility="local0")
#rhttpproxy init stderr
input(type="imfile"
      File="/var/log/vmware/rhttpproxy/rproxy_init.log.stderr"
      Tag="rhttpproxy-stderr"
      Severity="info"
      Facility="local0")'
  impact 0.5
  tag check_id: 'C-62903r935391_chk'
  tag severity: 'medium'
  tag gid: 'V-259163'
  tag rid: 'SV-259163r961395_rule'
  tag stig_id: 'VCRP-80-000073'
  tag gtitle: 'SRG-APP-000358-WSR-000063'
  tag fix_id: 'F-62812r935392_fix'
  tag satisfies: ['SRG-APP-000358-WSR-000063', 'SRG-APP-000125-WSR-000071']
  tag cci: ['CCI-001348', 'CCI-001851']
  tag nist: ['AU-9 (2)', 'AU-4 (1)']

  goodcontent = inspec.profile.file('vmware-services-rhttpproxy.conf')
  describe file('/etc/vmware-syslog/vmware-services-rhttpproxy.conf') do
    its('content') { should eq goodcontent }
  end
end
