# encoding: UTF-8

control 'VCLD-70-000002' do
  title "VAMI must be configured with FIPS 140-2 compliant ciphers for HTTPS
connections."
  desc  "Encryption of data in flight is an essential element of protecting
information confidentiality. If a web server uses weak or outdated encryption
algorithms, then the server's communications can potentially be compromised.

    The US Federal Information Processing Standards (FIPS) publication 140-2,
Security Requirements for Cryptographic Modules (FIPS 140-2), identifies eleven
areas for a cryptographic module used inside a security system that protects
information. FIPS 140-2 approved ciphers provide the maximum level of
encryption possible for a private web server.

    VAMI is compiled to use VMware's FIPS validated OpenSSL module and cannot
be configured otherwise. Ciphers may still be specified in order of preference,
but no non-FIPS approved ciphers will be implemented.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/sbin/vami-lighttpd -p -f
/opt/vmware/etc/lighttpd/lighttpd.conf|grep \"ssl.cipher-list\"|sed -e 's/^[
]*//'

    Expected result:

    ssl.cipher-list                   =
\"!aNULL:kECDH+AESGCM:ECDH+AESGCM:RSA+AESGCM:kECDH+AES:ECDH+AES:RSA+AES\"

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /etc/applmgmt/appliance/lighttpd.conf

    Add or reconfigure the following value:

    ssl.cipher-list                   =
\"!aNULL:kECDH+AESGCM:ECDH+AESGCM:RSA+AESGCM:kECDH+AES:ECDH+AES:RSA+AES\"
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000002'
  tag fix_id: nil
  tag cci: 'CCI-000068'
  tag nist: ['AC-17 (2)']

  runtime = command("#{input('lighttpdBin')} -p -f #{input('lighttpdConf')}").stdout

  describe parse_config(runtime).params['ssl.cipher-list'] do
    it { should cmp "#{input('sslCipherList')}" }
  end

end

