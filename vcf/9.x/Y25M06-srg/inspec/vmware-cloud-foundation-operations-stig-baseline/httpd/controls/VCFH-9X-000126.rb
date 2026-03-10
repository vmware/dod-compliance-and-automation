control 'VCFH-9X-000126' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service must protect against MIME sniffing.'
  desc  "
    MIME sniffing was, and still is, a technique used by some web browsers to examine the content of a particular asset. This is done for the purpose of determining an asset's file format. This technique is useful in the event that there is not enough metadata information present for a particular asset, thus leaving the possibility that the browser interprets the asset incorrectly.

    Although MIME sniffing can be useful to determine an asset's correct file format, it can also cause a security vulnerability. This vulnerability can be quite dangerous both for site owners as well as site visitors. This is because an attacker can leverage MIME sniffing to send an XSS (Cross Site Scripting) attack.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify a header is configured to set X-Content-Type-Options.

    At the command prompt, run the following:

    # cat /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | sed -n \"/^<VirtualHost\\s\\*:443>/,/<\\/VirtualHost>/p\" | grep -i \"Header\"

    Example output:

    Header set X-Content-Type-Options \"nosniff\"

    If a header directive is not present to configure \"X-Content-Type-Options\" as shown in the example, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Find the \"VirtualHost\" section listening on port 443 and add or update the following line:

    Header set X-Content-Type-Options \"nosniff\"

    Reload the configuration by running the following command:

    # systemctl reload httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-VCFH-9X-000126'
  tag rid: 'SV-VCFH-9X-000126'
  tag stig_id: 'VCFH-9X-000126'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  conf = input('apache_virtualhost_conf_file')
  apache_header_content_type_options = input('apache_header_content_type_options')

  # Make sure the conf file exists so the tests do not pass with false positives
  describe file(conf) do
    it { should exist }
  end

  header = command("cat #{conf} | sed -n \"/^<VirtualHost\\s\\*:443>/,/<\\/VirtualHost>/p\" | grep -i \"Header\" | grep -i \"X-Content-Type-Options\"").stdout.strip

  if !header.empty?
    describe 'The X-Content-Type-Options header' do
      subject { header }
      it { should cmp apache_header_content_type_options }
    end
  else
    describe 'The X-Content-Type-Options header' do
      subject { header }
      it { should_not be_empty }
    end
  end
end
