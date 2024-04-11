control 'VRPE-8X-000004' do
  title 'The VMware Aria Operations Apache server must capture, record, and log all content related to a user session.'
  desc  "
    A user session to a web server is in the context of a user accessing a hosted application that extends to any plug-ins/modules and services that may run on behalf of the user.

    The web server must be capable of enabling a setting for troubleshooting, debugging, or forensic gathering purposes which will log all user session information related to the hosted application session. Without the capability to capture, record, and log all content related to a user session, investigations into suspicious user activity would be hampered.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep CustomLog /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | sed 's/^[ \\t]*//' | grep -v '^#'

    Expected result:

    CustomLog \"|/usr/sbin/rotatelogs2 -n 35 /var/log/apache2/access_log 50M\" \"%h %l %u %t \\\"%r\\\" %>s %b \\\"%{Referer}i\\\" \\\"%{User-agent}i\\\" Agent-Token:%{SSL_CLIENT_S_DN_CN}x \" env=lather
    CustomLog \"|/usr/sbin/rotatelogs2 -n 35 /var/log/apache2/access_log 50M\" combined  env=!lather

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Update the CustomLog directives to:

    CustomLog \"|/usr/sbin/rotatelogs2 -n 35 /var/log/apache2/access_log 50M\" \"%h %l %u %t \\\"%r\\\" %>s %b \\\"%{Referer}i\\\" \\\"%{User-agent}i\\\" Agent-Token:%{SSL_CLIENT_S_DN_CN}x \" env=lather
    CustomLog \"|/usr/sbin/rotatelogs2 -n 35 /var/log/apache2/access_log 50M\" combined  env=!lather

    Save and close.

    At the command prompt, run the following command:

    # systemctl restart httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000093-WSR-000053'
  tag satisfies: ['SRG-APP-000016-WSR-000005', 'SRG-APP-000089-WSR-000047', 'SRG-APP-000092-WSR-000055', 'SRG-APP-000095-WSR-000056', 'SRG-APP-000096-WSR-000057', 'SRG-APP-000097-WSR-000058', 'SRG-APP-000098-WSR-000059', 'SRG-APP-000099-WSR-000061', 'SRG-APP-000100-WSR-000064', 'SRG-APP-000374-WSR-000172', 'SRG-APP-000375-WSR-000171']
  tag gid: 'V-VRPE-8X-000004'
  tag rid: 'SV-VRPE-8X-000004'
  tag stig_id: 'VRPE-8X-000004'
  tag cci: ['CCI-000067', 'CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000169', 'CCI-001462', 'CCI-001464', 'CCI-001487', 'CCI-001889', 'CCI-001890']
  tag nist: ['AC-17 (1)', 'AU-12 a', 'AU-14 (1)', 'AU-14 (2)', 'AU-3', 'AU-8 b']

  customlogs = input('customLogSettings')

  # Remove spaces and tabs at the beginnings of the lines returned
  result = command("grep CustomLog #{input('apacheConfPath')} | sed 's/^[ \\t]*//' | grep -v '^#'")

  # Split the lines returned, compare each to the given array of allowed values (strip out all spaces on the compare)
  result.stdout.split("\n").each do |item|
    matchfound = false
    customlogs.each do |custom|
      next unless item.gsub(' ', '').eql?(custom.gsub(' ', ''))
      matchfound = true
      describe 'Evaluating CustomLog setting' do
        subject { item.gsub(' ', '') }
        it { should cmp custom.gsub(' ', '') }
      end
    end

    next if matchfound
    describe item do
      it { should be_in customlogs }
    end
  end
end
