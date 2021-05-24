# encoding: UTF-8

control 'VCLD-70-000001' do
  title 'VAMI must limit the number of simultaneous requests.'
  desc  "Denial of service (DoS) is one threat against web servers.  Many DoS
attacks attempt to consume web server resources in such a way that no more
resources are available to satisfy legitimate requests.  Mitigation against
these threats is to take steps to  limit the number of resources that can be
consumed in certain ways.

    VAMI provides the maxConnections attribute of the <Connector Elements> to
limit the number of concurrent TCP connections. This comes per-configured with
a tested, supported value that must be verified and maintained.

  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep \"server.max-connections\" /opt/vmware/etc/lighttpd/lighttpd.conf

    Expected result:

    server.max-connections = 1024

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /opt/vmware/etc/lighttpd/lighttpd.conf

    Add or reconfigure the following value:

    server.max-connections = 1024
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000001'
  tag fix_id: nil
  tag cci: 'CCI-000054'
  tag nist: ['AC-10']

  runtime = command("#{input('lighttpdBin')} -p -f #{input('lighttpdConf')}").stdout

  describe parse_config(runtime).params['server.max-connections'] do
    it { should cmp "#{input('serverMaxConnections')}" }
  end

end

