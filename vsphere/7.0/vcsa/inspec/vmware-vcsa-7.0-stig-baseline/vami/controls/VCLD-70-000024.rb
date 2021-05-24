# encoding: UTF-8

control 'VCLD-70-000024' do
  title 'VAMI must implement TLS1.2 exclusively.'
  desc  "Transport Layer Security (TLS) is a required transmission protocol for
a web server hosting controlled information. The use of TLS provides
confidentiality of data in transit between the web server and client. FIPS
140-2 approved TLS versions must be enabled, and non-FIPS-approved SSL versions
must be disabled.

    VAMI comes configured to use only TLS 1.2. This configuration mus be
verified and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/sbin/vami-lighttpd -p -f
/opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep \"ssl.use\"|sed 's: ::g'

    Expected result:

    ssl.use-sslv2=\"disable\"
    ssl.use-sslv3=\"disable\"
    ssl.use-tlsv10=\"disable\"
    ssl.use-tlsv11=\"disable\"
    ssl.use-tlsv12=\"enable\"

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /opt/vmware/etc/lighttpd/lighttpd.conf

    Replace any and all \"ssl.use-*\" lines with following:

    ssl.use-sslv2=\"disable\"
    ssl.use-sslv3=\"disable\"
    ssl.use-tlsv10=\"disable\"
    ssl.use-tlsv11=\"disable\"
    ssl.use-tlsv12=\"enable\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000439-WSR-000156'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000024'
  tag fix_id: nil
  tag cci: 'CCI-002418'
  tag nist: ['SC-8']

  runtime = command("#{input('lighttpdBin')} -p -f #{input('lighttpdConf')}").stdout

  describe parse_config(runtime).params['ssl.use-sslv2'] do
    it { should cmp "\"disable\"" }
  end

  describe parse_config(runtime).params['ssl.use-sslv3'] do
    it { should cmp "\"disable\"" }
  end

  describe parse_config(runtime).params['ssl.use-tlsv10'] do
    it { should cmp "\"disable\"" }
  end

  describe parse_config(runtime).params['ssl.use-tlsv11'] do
    it { should cmp "\"disable\"" }
  end

  describe parse_config(runtime).params['ssl.use-tlsv12'] do
    it { should cmp "\"enable\"" }
  end

end

