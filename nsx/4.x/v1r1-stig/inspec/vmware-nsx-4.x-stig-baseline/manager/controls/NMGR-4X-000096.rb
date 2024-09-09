control 'NMGR-4X-000096' do
  title 'The NSX Manager must be running a release that is currently supported by the vendor.'
  desc 'Network devices running an unsupported operating system lack current security fixes required to mitigate the risks associated with recent vulnerabilities.'
  desc 'check', '
    From the NSX Manager web interface, go to the System >> Lifecycle Management >> Upgrade.

    If the NSX Manager current version is not the latest approved for use in DOD and supported by the vendor, this is a finding.
  '
  desc 'fix', '
    To upgrade NSX, reference the upgrade guide in the documentation for the relevant version being upgraded. Refer to the NSX documentation and release notes for information on the latest releases.

    https://docs.vmware.com/en/VMware-NSX/index.html

    If NSX is part of a VMware Cloud Foundation deployment, refer to that documentation for latest supported versions and upgrade guidance.
  '
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-NDM-000351'
  tag gid: 'V-263224'
  tag rid: 'SV-263224r977439_rule'
  tag stig_id: 'NMGR-4X-000096'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  result = http("https://#{input('nsxManager')}/api/v1/upgrade/nodes",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                  'Cookie' => "#{input('sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    nodes = JSON.parse(result.body)
    nodes['results'].each do |node|
      next unless node['component_version'] != 'Pending'
      describe "Node: #{node['display_name']} of Type: #{node['type']} with Version: #{node['component_version']} its" do
        subject { json(content: node.to_json) }
        its('component_version') { should match "#{input('nsxtVersion')}" }
      end
    end
  end
end
