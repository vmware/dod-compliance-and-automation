control 'CDAP-10-000136' do
  title 'Cloud Director must configure a test connection denylist.'
  desc  "
    Starting with VMware Cloud Director 10.1, service providers and tenants can use the VMware Cloud Director API to test connections to remote servers and to verify the server identity as part of an SSL handshake.

    To protect the internal network in which a VMware Cloud Director instance is deployed from malicious attacks, system providers can configure a denylist of internal hosts that are unreachable to tenants.

    This way, if a malicious attacker with tenant access attempts to use the connection testing VMware Cloud Director API to map the network in which VMware Cloud Director is installed, they won't be able to connect to the internal hosts on the denylist.

    After installation or upgrade and before providing tenants with access to the VMware Cloud Director network, use the manage-test-connection-blacklist command of the cell management tool to block tenant access to internal hosts.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify a test connect deny list exists by running the following command:

    #  /opt/vmware/vcloud-director/bin/cell-management-tool manage-test-connection-denylist --list

    Example output:

    listed connection items:
    Connection specification: \"internal.com\"
    Connection specification: \"10.0.0.0/8\"

    If there are no denylist connection items listed, this is a finding.
  "
  desc 'fix', "
    To add a specific IP to the deny list at the command prompt, execute the following command:

    # /opt/vmware/vcloud-director/bin/cell-management-tool manage-test-connection-denylist --add-ip 192.168.1.2

    or

    To add an IP range to the deny list at the command prompt, execute the following command:

    # /opt/vmware/vcloud-director/bin/cell-management-tool manage-test-connection-denylist --add-range 10.0.0.0/8

    or

    To add a domain name to the deny list at the command prompt, execute the following command:

    # /opt/vmware/vcloud-director/bin/cell-management-tool manage-test-connection-denylist --add-name internal.com
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CDAP-10-000136'
  tag rid: 'SV-CDAP-10-000136'
  tag stig_id: 'CDAP-10-000136'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  approvedDenyLists = input('approvedDenyLists')
  result = command('/opt/vmware/vcloud-director/bin/cell-management-tool manage-test-connection-denylist --list | grep Connection').stdout
  denylists = result.strip.split("\n")

  if !denylists.empty?
    denylists.each do |denylist|
      denylist = denylist.scan(/Connection specification: "(.*)"/).flatten
      describe denylist do
        it { should be_in approvedDenyLists }
      end
    end
  else
    describe 'Test Connection Deny List' do
      subject { result }
      it { should_not be_empty }
    end
  end
end
