control 'VRPE-8X-000024' do
  title 'The VMware Aria Operations Apache server must employ cryptographic mechanisms (TLS/DTLS/SSL) preventing the unauthorized disclosure of information during transmission.'
  desc  "
    Preventing the disclosure of transmitted information requires that the web server take measures to employ some form of cryptographic mechanism in order to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS).

    Transmission of data can take place between the web server and a large number of devices/applications external to the web server. Examples are a web client used by a user, a backend database, an audit server, or other web servers in a web cluster.

    If data is transmitted unencrypted, the data then becomes vulnerable to disclosure. The disclosure may reveal user identifier/password combinations, website code revealing business logic, or other user personal information.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep SSLProtocol /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | grep -v '^#'

    Expected result:

    SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Add or configure the following line:

    SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1

    Save and close.

    At the command prompt, run the following command:

    # systemctl restart httpd
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000439-WSR-000151'
  tag satisfies: ['SRG-APP-000172-WSR-000104', 'SRG-APP-000439-WSR-000152', 'SRG-APP-000439-WSR-000156', 'SRG-APP-000442-WSR-000182']
  tag gid: 'V-VRPE-8X-000024'
  tag rid: 'SV-VRPE-8X-000024'
  tag stig_id: 'VRPE-8X-000024'
  tag cci: ['CCI-000197', 'CCI-002418', 'CCI-002422']
  tag nist: ['IA-5 (1) (c)', 'SC-8', 'SC-8 (2)']

  describe apache_conf(input('apacheConfPath')) do
    its('SSLProtocol') { should cmp 'All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1' }
  end
end
