# encoding: UTF-8

control 'VCLD-70-000003' do
  title "VAMI must use cryptography to protect the integrity of remote
sessions."
  desc  "Data exchanged between the user and the web server can range from
static display data to credentials used to log into the hosted application.
Even when data appears to be static, the non-displayed logic in a web page may
expose business logic or trusted system relationships. The integrity of all the
data being exchanged between the user and web server must always be trusted. To
protect the integrity and trust, encryption methods should be used to protect
the complete communication session.

    In order to protect the integrity and confidentiality of the remote
sessions, VAMI uses SSL/TLS.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/sbin/vami-lighttpd -p -f
/opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep \"ssl.engine\"|sed -e
's/^[ ]*//'

    Expected result:

    ssl.engine                 = \"enable\"

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

    Add or reconfigure the following value:

    ssl.engine = \"enable\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000015-WSR-000014'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000003'
  tag fix_id: nil
  tag cci: 'CCI-001453'
  tag nist: ['AC-17 (2)']

  runtime = command("#{input('lighttpdBin')} -p -f #{input('lighttpdConf')}").stdout

  describe parse_config(runtime).params['ssl.engine'] do
    it { should cmp "#{input('sslEngine')}" }
  end

end

