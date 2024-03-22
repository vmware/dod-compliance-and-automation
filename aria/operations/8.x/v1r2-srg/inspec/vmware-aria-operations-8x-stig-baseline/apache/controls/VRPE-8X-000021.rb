control 'VRPE-8X-000021' do
  title 'The vRealize Operations Manager Apache server must use a logging mechanism that is configured to allocate log record storage capacity large enough to accommodate the logging requirements of the web server.'
  desc  "
    In order to make certain that the logging mechanism used by the web server has sufficient storage capacity in which to write the logs, the logging mechanism needs to be able to allocate log record storage capacity.

    The task of allocating log record storage capacity is usually performed during initial installation of the logging mechanism. The system administrator will usually coordinate the allocation of physical drive space with the web server administrator along with the physical location of the partition and disk. Refer to NIST SP 800-92 for specific requirements on log rotation and storage dependent on the impact of the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep ErrorLog /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | sed 's/^[ \\t]*//' | grep -v '^#'

    Expected result:

    ErrorLog \"|/usr/sbin/rotatelogs2 -n 35 /var/log/apache2/error_log 50M\"

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Add or configure the following line:

    ErrorLog \"|/usr/sbin/rotatelogs2 -n 35 /var/log/apache2/error_log 50M\"

    Save and close.

    At the command prompt, run the following command:

    # systemctl restart httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000357-WSR-000150'
  tag gid: 'V-VRPE-8X-000021'
  tag rid: 'SV-VRPE-8X-000021'
  tag stig_id: 'VRPE-8X-000021'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

  describe apache_conf(input('apacheConfPath')) do
    its('ErrorLog') { should cmp '|/usr/sbin/rotatelogs2 -n 35 /var/log/apache2/error_log 50M' }
  end
end
