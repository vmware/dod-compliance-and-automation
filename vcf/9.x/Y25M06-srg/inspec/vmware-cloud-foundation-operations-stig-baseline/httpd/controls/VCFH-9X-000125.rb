control 'VCFH-9X-000125' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service must prevent rendering inside a frame or iframe on another site.'
  desc  "
    Clickjacking, also known as a “UI redress attack”, is when an attacker uses multiple transparent or opaque layers to trick a user into clicking on a button or link on another page when they were intending to click on the top level page. Thus, the attacker is “hijacking” clicks meant for their page and routing them to another page, most likely owned by another application, domain, or both.

    Using a similar technique, keystrokes can also be hijacked. With a carefully crafted combination of stylesheets, iframes, and text boxes, a user can be led to believe they are typing in the password to their email or bank account, but are instead typing into an invisible frame controlled by the attacker.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify a header is present to configure X-Frame-Options.

    At the command prompt, run the following:

    # cat /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | sed -n \"/^<VirtualHost\\s\\*:443>/,/<\\/VirtualHost>/p\" | grep -i \"Header\"

    Example output:

    Header set X-Frame-Options \"SAMEORIGIN\"

    If a header directive is not present to configure \"X-Frame-Options\" as shown in the example, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Find the \"VirtualHost\" section listening on port 443 and add or update the following line:

    Header set X-Frame-Options \"SAMEORIGIN\"

    Reload the configuration by running the following command:

    # systemctl reload httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-VCFH-9X-000125'
  tag rid: 'SV-VCFH-9X-000125'
  tag stig_id: 'VCFH-9X-000125'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  conf = input('apache_virtualhost_conf_file')
  apache_header_xframe_options = input('apache_header_xframe_options')

  # Make sure the conf file exists so the tests do not pass with false positives
  describe file(conf) do
    it { should exist }
  end

  header = command("cat #{conf} | sed -n \"/^<VirtualHost\\s\\*:443>/,/<\\/VirtualHost>/p\" | grep -i \"Header\" | grep -i \"X-Frame-Options\"").stdout.strip

  if !header.empty?
    describe 'The X-Frame-Options header' do
      subject { header }
      it { should cmp apache_header_xframe_options }
    end
  else
    describe 'The X-Frame-Options header' do
      subject { header }
      it { should_not be_empty }
    end
  end
end
