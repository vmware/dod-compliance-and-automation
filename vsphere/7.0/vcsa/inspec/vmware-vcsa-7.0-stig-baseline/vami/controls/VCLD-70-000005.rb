# encoding: UTF-8

control 'VCLD-70-000005' do
  title 'VAMI must generate log records for system startup and shutdown.'
  desc  "Logging must be started as soon as possible when a service starts and
when a service is stopped. Many forms of suspicious actions can be
detected by analyzing logs for unexpected service starts and stops.
Also, by starting to log immediately after a service starts, it becomes
more difficult for suspicous activity to go unlogged."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/sbin/vami-lighttpd -p -f
/opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep \"server.errorlog\"|sed
-e 's/^[ ]*//'

    Expected result:

    server.errorlog                   =
\"/opt/vmware/var/log/lighttpd/error.log\"

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /opt/vmware/etc/lighttpd/lighttpd.conf

    Add or reconfigure the following value:

    server.errorlog = \"/opt/vmware/var/log/lighttpd/error.log\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000005'
  tag fix_id: nil
  tag cci: 'CCI-000169'
  tag nist: ['AU-12 a']

  runtime = command("#{input('lighttpdBin')} -p -f #{input('lighttpdConf')}").stdout

  describe parse_config(runtime).params['server.errorlog'] do
    it { should cmp "#{input('errorLog')}" }
  end
  
end

