control 'VCFH-9X-000063' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service must load the http2 module.'
  desc  "
    Request smuggling attacks involve placing both the Content-Length header and the Transfer-Encoding header into a single HTTP/1 request and manipulating it so that web servers (i.e., back-end, front-end, load balancers) process the request differently. There are a number of variants of this type of attack with different names. However, all variants are addressed by configuring the front-end server to exclusively use HTTP/2 when communicating with other web servers. Specific instances of this vulnerability can be resolved by reconfiguring the front-end server to normalize ambiguous requests before routing them onward.  However, if the request cannot be made unambiguous or normalized, configure both the front-end and back-end servers to reject the message and close the connection.

    It is important to not assume requests do not have a body. For all web servers, examine requests that report message body length as zero in the HTTP header and drop the request.

    For load balancing or reverse proxying implementation:
    -The front-end web server must interpret and forward HTTP requests, such that the back-end server receives a consistent interpretation of the request, or terminate the TCP connection.
    -The back-end web server must drop ambiguous requests that cannot be normalized and terminate the TCP connection.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the \"http2_module\" is present.

    At the command prompt, run the following:

    # httpd -M | grep -i \"http2_module\"

    Example output:

    http2_module (shared)

    If the \"http2_module\" is not found, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/httpd/conf/httpd.conf

    Add or update the following line:

    LoadModule http2_module /usr/lib/httpd/modules/mod_http2.so

    Restart the service by running the following command:

    # systemctl restart httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000251-WSR-000194'
  tag satisfies: ['SRG-APP-000251-WSR-000195']
  tag gid: 'V-VCFH-9X-000063'
  tag rid: 'SV-VCFH-9X-000063'
  tag stig_id: 'VCFH-9X-000063'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']

  # Get an array of loaded modules and split on line returns
  modules = command('httpd -M | grep -v "Loaded Modules:"').stdout.split("\n")

  # Interate through each loaded module to see if http2_module is present
  if !modules.nil?
    h2modfound = false
    modules.each do |mod|
      modname = mod.split(' ')[0]
      next unless modname == 'http2_module'
      h2modfound = true
      describe 'The loaded modules list' do
        subject { modname }
        it { should cmp 'http2_module' }
      end
    end
    unless h2modfound
      describe 'http2_module found' do
        subject { h2modfound }
        it { should cmp true }
      end
    end
  else
    describe 'No loaded modules found...skipping...' do
      skip 'No loaded modules found...skipping...'
    end
  end
end
