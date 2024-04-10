control 'VRPE-8X-000002' do
  title 'The VMware Aria Operations Apache server must use encryption strength in accordance with the categorization of data hosted by the web server when remote connections are provided.'
  desc  "
    The web server has several remote communications channels. Examples are user requests via http/https, communication to a backend database, or communication to authenticate users. The encryption used to communicate must match the data that is being retrieved or presented.

    Methods of communication are http for publicly displayed information, https to encrypt when user data is being transmitted, VPN tunneling, or other encryption methods to a database.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep SSLCipherSuite /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | grep -v '^#'

    Expected result:

    SSLCipherSuite HIGH:!aNULL!ADH:!EXP:!MD5:!3DES:!CAMELLIA:!PSK:!SRP:!DH:!AES256-GCM-SHA384:!AES256-SHA256:!AES256-SHA:!AES128-GCM-SHA256:!AES128-SHA256:!AES128-SHA:@STRENGTH

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Add or configure the following line:

    SSLCipherSuite HIGH:!aNULL!ADH:!EXP:!MD5:!3DES:!CAMELLIA:!PSK:!SRP:!DH:!AES256-GCM-SHA384:!AES256-SHA256:!AES256-SHA:!AES128-GCM-SHA256:!AES128-SHA256:!AES128-SHA:@STRENGTH

    Save and close.

    At the command prompt, run the following command:

    # systemctl restart httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag satisfies: ['SRG-APP-000416-WSR-000118', 'SRG-APP-000439-WSR-000188']
  tag gid: 'V-VRPE-8X-000002'
  tag rid: 'SV-VRPE-8X-000002'
  tag stig_id: 'VRPE-8X-000002'
  tag cci: ['CCI-000068', 'CCI-002418', 'CCI-002450']
  tag nist: ['AC-17 (2)', 'SC-13', 'SC-8']

  describe apache_conf(input('apacheConfPath')) do
    its('SSLCipherSuite') { should cmp input('sslCipherSuite') }
  end
end
