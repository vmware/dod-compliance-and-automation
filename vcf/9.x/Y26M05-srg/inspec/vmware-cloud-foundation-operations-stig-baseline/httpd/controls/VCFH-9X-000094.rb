control 'VCFH-9X-000094' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service must enable HTTP/2. '
  desc  "
    HTTP/2, like HTTPS, enhances security compared to HTTP/1.x by minimizing the risk of header-based attacks (e.g., header injection and manipulation).

    Websites that fully utilize HTTP/2 are inherently protected and defend against smuggling attacks. HTTP/2 provides the method for specifying the length of a request, which removes any potential for ambiguity that can be leveraged by an attacker.

    This is applicable to all web architectures such as load balancing/proxy use cases.
    - The front-end and back-end servers should both be configured to use HTTP/2.
    - HTTP/2 must be used for communications between web servers.
    - Browser vendors have agreed to only support HTTP/2 only in HTTPS mode, thus TLS must be configured to meet this requirement. TLS configuration is out of scope for this requirement.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that the http/2 protocol is enabled..

    At the command prompt, run the following:

    # cat /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | sed -n \"/^<VirtualHost\\s\\*:443>/,/<\\/VirtualHost>/p\" | grep -i \"Protocols\"

    Example output:

    Protocols h2 h2c http/1.1

    If the value of \"Protocols\" does not include \"h2\" first, this is a finding.

    Note: By default, the first one is the most preferred protocol.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Note: If the offending configuration was found in a different file edit that file instead.

    Find the \"VirtualHost\" section listening on port 443 and add or update the following line ensuring \"h2\" is first:

    Protocols h2 h2c http/1.1

    Reload the configuration by running the following command:

    # systemctl reload httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000439-WSR-000192'
  tag gid: 'V-VCFH-9X-000094'
  tag rid: 'SV-VCFH-9X-000094'
  tag stig_id: 'VCFH-9X-000094'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

  conf = input('apache_virtualhost_conf_file')
  protocols_header = input('apache_header_protocols')

  # Make sure the conf file exists so the tests do not pass with false positives
  describe file(conf) do
    it { should exist }
  end

  protocols = command("cat #{conf} | sed -n \"/^<VirtualHost\\s\\*:443>/,/<\\/VirtualHost>/p\" | grep -i \"Protocols\"").stdout.strip

  if !protocols.nil?
    describe "Protocol directive: #{protocols}" do
      subject { protocols }
      it { should cmp protocols_header }
    end
  else
    describe 'Protocol directive' do
      subject { protocols }
      it { should_not be_nil }
    end
  end
end
