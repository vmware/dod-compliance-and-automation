# encoding: UTF-8

control 'VCLD-70-000026' do
  title 'VAMI must disable client initiated TLS renegotiation.'
  desc  "All versions of the SSL and TLS protocols (up to and including
TLS/1.2) are vulnerable to a Man-in-the-Middle attack (CVE-2009-3555) during a
renegotiation. This vulnerability allowed an attacker to \"prefix\" a chosen
plaintext to the HTTP request as seen by the web server. The protocols have
since been ammended by RFC5746 but the fix must be supported by both client and
server to be effective.

    While lighttpd and the underlying openssl libraries are no longer
vulnerable, steps must be taken to account for older clients that do not
support RFC5746. To this end, lighttpd disables client initiated renegotiation
entirely by default. This configuration must be validated and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/sbin/vami-lighttpd -p -f
/opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep
\"ssl\\.disable-client-renegotiation\"|sed 's: ::g'

    If no line is returned, this is NOT a finding.

    If \"ssl.disable-client-renegotiation\" is set to \"disabled\", this is a
finding.
  "
  desc  'fix', "
    Navigate to and open:

    /opt/vmware/etc/lighttpd/lighttpd.conf

    Remove any setting for \"ssl.disable-client-renegotiation\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000026'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  runtime = command("#{input('lighttpdBin')} -p -f #{input('lighttpdConf')}").stdout

  describe.one do

    describe parse_config(runtime).params['ssl.disable-client-renegotiation'] do
      it { should cmp nil }
    end

    describe parse_config(runtime).params['ssl.disable-client-renegotiation'] do
      it { should cmp "\"enabled\"" }
    end
  
  end

end

