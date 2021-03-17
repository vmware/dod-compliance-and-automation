# encoding: UTF-8

control 'VCLD-70-000025' do
  title 'VAMI must force clients to select the most secure cipher.'
  desc  "During a TLS session negotiation, when choosing a cipher during a
handshake, normally the client's preference is used. This is potentially
problematic as a malicious, dated or pooly configured client could select the
most insecure cipher offered by the server, even if it supports stronger ones.
If \"ssl.honor-cipher-order\" is enabled, then the \"ssl.cipher-list\" setting
will be treated as an ordered list of cipher values from most preferred to
least, left to right."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/sbin/vami-lighttpd -p -f
/opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep
\"ssl\\.honor-cipher-order\"|sed 's: ::g'

    Expected result:

    ssl.honor-cipher-order = \"enable\"

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

    Add or reconfigure the following setting:

    ssl.honor-cipher-order = \"enable\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000025'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  runtime = command("#{input('lighttpdBin')} -p -f #{input('lighttpdConf')}").stdout

  describe parse_config(runtime).params['ssl.honor-cipher-order'] do
    it { should cmp "#{input('sslHonorCipherOrder')}" }
  end

end

