control 'VRPE-8X-000023' do
  title 'The VMware Aria Operations Apache server must be tuned to handle the operational requirements of the hosted application.'
  desc  'A Denial of Service (DoS) can occur when the web server is so overwhelmed that it can no longer respond to additional requests. A web server not properly tuned may become overwhelmed and cause a DoS condition even with expected traffic from users. To avoid a DoS, the web server must be tuned to handle the expected traffic for the hosted applications.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep -E \"LimitRequestLine|LimitRequestFieldSize\" /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | sed 's/^\\s*//' | grep -v '^#'

    Expected result:

    LimitRequestLine 1048576
    LimitRequestFieldSize 16384

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Add or configure the following lines inside the \"<VirtualHost *:443>\" block:

    LimitRequestLine 1048576
    LimitRequestFieldSize 16384

    Save and close.

    At the command prompt, run the following command:

    # systemctl restart httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000435-WSR-000148'
  tag gid: 'V-VRPE-8X-000023'
  tag rid: 'SV-VRPE-8X-000023'
  tag stig_id: 'VRPE-8X-000023'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5']

  describe apache_conf(input('apacheConfPath')) do
    its('LimitRequestLine') { should cmp '1048576' }
    its('LimitRequestFieldSize') { should cmp '16384' }
  end
end
