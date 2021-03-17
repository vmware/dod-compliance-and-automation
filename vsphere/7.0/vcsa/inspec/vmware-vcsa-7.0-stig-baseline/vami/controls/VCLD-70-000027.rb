# encoding: UTF-8

control 'VCLD-70-000027' do
  title "VAMI must be configured to hide the server type and version in client
responses."
  desc  "Web servers will often display error messages to client users
displaying enough information to aid in the debugging of the error. The
information given back in error messages may display the web server type,
version, patches installed, plug-ins and modules installed, type of code being
used by the hosted application, and any backends being used for data storage.
This information could be used by an attacker to blueprint what type of attacks
might be successful. As such, VAMI must be configured to hide the server
version at all times."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/sbin/vami-lighttpd -p -f
/opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep \"server.tag\"|sed 's:
::g'

    Expected result:

    server.tag=\"vami\"

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open /etc/applmgmt/appliance/lighttpd.conf

    Add or reconfigure the following value:

    server.tag = \"vami\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000027'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  runtime = command("#{input('lighttpdBin')} -p -f #{input('lighttpdConf')}").stdout

  describe parse_config(runtime).params['server.tag'] do
    it { should cmp "#{input('serverTag')}" }
  end

end

