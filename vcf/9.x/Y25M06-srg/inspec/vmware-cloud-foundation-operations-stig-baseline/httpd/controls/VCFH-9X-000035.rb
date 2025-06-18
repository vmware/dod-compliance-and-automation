control 'VCFH-9X-000035' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service must constrain users and scripts running on behalf of users to the document root or home directory tree of the web server.'
  desc  "
    A web server is designed to deliver content and execute scripts or applications on the request of a client or user.  Constraining user requests to files in the directory tree of the hosted web application and limiting the execution of scripts and applications guarantees that the user is not accessing information protected outside the application's realm.

    The web server must also prohibit users from jumping outside the hosted application directory tree through access to the user's home directory, symbolic links or shortcuts, or through search paths for missing files.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the \"Directory\" directive for the root path is restricted.

    At the command prompt, run the following:

    # cat /etc/httpd/conf/httpd.conf | sed -n \"/^<Directory\\s\\/>/,/<\\/Directory>/p\"

    Example output:

    <Directory />
        AllowOverride none
        Require all denied
    </Directory>

    If the output from the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/httpd/conf/httpd.conf

    Find the <Directory /> directive for the default \"/\" path and add or update it as follows:

    <Directory />
        AllowOverride none
        Require all denied
    </Directory>

    Reload the configuration by running the following command:

    # systemctl reload httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000087'
  tag satisfies: ['SRG-APP-000266-WSR-000142']
  tag gid: 'V-VCFH-9X-000035'
  tag rid: 'SV-VCFH-9X-000035'
  tag stig_id: 'VCFH-9X-000035'
  tag cci: ['CCI-000381', 'CCI-001312']
  tag nist: ['CM-7 a', 'SI-11 a']

  conf = input('apache_httpd_conf_file')

  # Make sure the conf file exists so the tests do not pass with false positives
  describe file(conf) do
    it { should exist }
  end

  directory = command("cat #{conf} | sed -n \"/^<Directory\\s\\/>/,/<\\/Directory>/p\"").stdout.gsub(/[\r\n\s]/, '')

  if !directory.empty?
    describe 'The Directory directive for the default path /' do
      subject { directory }
      it { should cmp '<Directory/>AllowOverridenoneRequirealldenied</Directory>' }
    end
  else
    describe 'Directory /' do
      subject { directory }
      it { should_not be_empty }
    end
  end
end
