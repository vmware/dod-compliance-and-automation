control 'VRPE-8X-000003' do
  title 'The VMware Aria Operations Apache server must use cryptography to protect the integrity of remote sessions.'
  desc  'Data exchanged between the user and the web server can range from static display data to credentials used to log into the hosted application. Even when data appears to be static, the non-displayed logic in a web page may expose business logic or trusted system relationships. The integrity of all the data being exchanged between the user and web server must always be trusted. To protect the integrity and trust, encryption methods must be used to protect the complete communication session.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep SSLEngine /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | sed 's/^[ \\t]*//' | grep -v '^#'

    Expected result:

    SSLEngine on

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Add or configure the following line:

    SSLEngine on

    Save and close.

    At the command prompt, run the following command:

    # systemctl restart httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000015-WSR-000014'
  tag gid: 'V-VRPE-8X-000003'
  tag rid: 'SV-VRPE-8X-000003'
  tag stig_id: 'VRPE-8X-000003'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']

  ssl_found = false

  input('apacheConfFiles').each do |conf|
    next if apache_conf(conf).SSLEngine.nil?
    ssl_found = true
    describe apache_conf(input('apacheConfPath')) do
      its('SSLEngine') { should cmp 'on' }
    end
  end

  unless ssl_found
    describe 'SSL Engine must be enabled' do
      subject { ssl_found }
      it { should cmp true }
    end
  end
end
