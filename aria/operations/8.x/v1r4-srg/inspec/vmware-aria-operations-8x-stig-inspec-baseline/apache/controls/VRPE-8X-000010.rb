control 'VRPE-8X-000010' do
  title 'The VMware Aria Operations Apache servers users and scripts running on behalf of users must be contained to the document root or home directory tree of the web server.'
  desc  "
    A web server is designed to deliver content and run scripts or applications on the request of a client or user.  Containing user requests to files in the directory tree of the hosted web application and limiting the running of scripts and applications helps to guarantee that the user is not accessing protected information outside the application's realm.

    The web server must also prohibit users from jumping outside the hosted application directory tree through access to the user's home directory, symbolic links or shortcuts, or through search paths for missing files.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # sed -n '/<Location \\/>/,/<\\/Location>/p' /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Expected result:

    <Location />
    <LimitExcept GET POST PUT DELETE PATCH>
    order deny,allow
    deny from all
    </LimitExcept>
    </Location>

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Add or change the following lines:

    <Location />
    <LimitExcept GET POST PUT DELETE PATCH>
    order deny,allow
    deny from all
    </LimitExcept>
    </Location>

    Save and close.

    At the command prompt, run the following command:

    # systemctl restart httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000087'
  tag gid: 'V-VRPE-8X-000010'
  tag rid: 'SV-VRPE-8X-000010'
  tag stig_id: 'VRPE-8X-000010'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe command("sed -n '/<Location \\/>/,/<\\/Location>/p' #{input('apacheConfPath')} ") do
    its('stdout.strip') { should cmp "<Location />\n<LimitExcept GET POST PUT DELETE PATCH>\norder deny,allow\ndeny from all\n</LimitExcept>\n</Location>" }
  end
end
