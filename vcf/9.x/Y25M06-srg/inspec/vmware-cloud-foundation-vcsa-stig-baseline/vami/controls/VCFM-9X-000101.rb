control 'VCFM-9X-000101' do
  title 'The VMware Cloud Foundation vCenter VAMI Lighttpd service must disable client initiated TLS renegotiation.'
  desc  "
    All versions of the Secure Sockets Layer (SSL) and TLS protocols (up to and including TLS 1.2) are vulnerable to a man-in-the-middle attack (CVE-2009-3555) during a renegotiation. This vulnerability allows an attacker to \"prefix\" a chosen plaintext to the HTTP request as seen by the web server. The protocols have since been amended by RFC 5746, but the fix must be supported by both client and server to be effective.

    While Lighttpd and the underlying OpenSSL libraries are no longer vulnerable, steps must be taken to account for older clients that do not support RFC 5746. To this end, Lighttpd disables client-initiated renegotiation entirely by default. This configuration must be validated and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # /usr/sbin/lighttpd -p -f /etc/lighttpd/lighttpd.conf 2>/dev/null|grep \"ssl\\.disable-client-renegotiation\"

    If no line is returned, this is not a finding.

    If \"ssl.disable-client-renegotiation\" is set to \"disabled\", this is a finding.

    Note: The command must be run from a bash shell and not from a shell generated by the \"appliance shell\". Use the \"chsh\" command to change the shell for the account to \"/bin/bash\". Refer to KB Article 2100508 for more details:

    https://knowledge.broadcom.com/external/article?legacyId=2100508
  "
  desc 'fix', "
    Navigate to and open:

    /etc/applmgmt/appliance/applmgmt-lighttpd.conf

    Remove any setting for \"ssl.disable-client-renegotiation\".

    Restart the service with the following command:

    # systemctl restart lighttpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-VCFM-9X-000101'
  tag rid: 'SV-VCFM-9X-000101'
  tag stig_id: 'VCFM-9X-000101'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  runtime = command("#{input('lighttpdBin')} -p -f #{input('lighttpdConf')}").stdout

  describe.one do
    describe parse_config(runtime).params['ssl.disable-client-renegotiation'] do
      it { should cmp nil }
    end
    describe parse_config(runtime).params['ssl.disable-client-renegotiation'] do
      it { should cmp '"enabled"' }
    end
  end
end
