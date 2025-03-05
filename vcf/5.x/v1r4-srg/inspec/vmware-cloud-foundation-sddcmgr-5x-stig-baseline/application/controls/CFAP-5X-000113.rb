control 'CFAP-5X-000113' do
  title 'The SDDC Manager must have all security patches and updates installed.'
  desc  'Installing software updates is a fundamental mitigation against the exploitation of publicly known vulnerabilities.'
  desc  'rationale', ''
  desc  'check', "
    SDDC Manager and Cloud Foundation updates are generally released as a group update to the bill of materials for a given VCF release. The SDDC manager orchestrates the installation of update to the management and workload domain components such as vSphere and NSX.

    Check for and download available updates by using either the online or offline process.

    Online:

    From the SDDC Manager UI, navigate to Lifecycle Management >> Bundle Management.

    Download available bundles shown if any.

    Offline:

    Follow the process at the URL below to download bundles offline.

    https://docs.vmware.com/en/VMware-Cloud-Foundation/5.0/vcf-lifecycle/GUID-8FA44ACE-8F04-47DA-845E-E0863094F7B0.html

    To review update applicability:

    From the SDDC Manager UI, navigate to Inventory >> Workload Domains.

    Select each management or workload domain and go to the Updates/Patches tab and review the Available Updates section.

    If SDDC Manager does not have the latest patches/updates installed, this is a finding.

    If SDDC Manager is not on a supported release, this is a finding.
  "
  desc 'fix', "
    To apply patches and updates to SDDC Manager/Cloud Foundation follow the guidance in the Lifecycle Management section found at the URL below.

    https://docs.vmware.com/en/VMware-Cloud-Foundation/5.0/vcf-lifecycle/GUID-B384B08D-3652-45E2-8AA9-AF53066F5F70.html
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000456-AS-000266'
  tag gid: 'V-CFAP-5X-000113'
  tag rid: 'SV-CFAP-5X-000113'
  tag stig_id: 'CFAP-5X-000113'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']

  currentVersion = input('currentVersion')

  result = http("https://#{input('sddcManager')}/v1/sddc-managers",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'Authorization' => "#{input('bearerToken')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    servers = JSON.parse(result.body)
    if servers.empty?
      describe 'No SDDC Manager version information returned.' do
        subject { servers }
        it { should_not be_empty }
      end
    else
      servers['elements'].each do |server|
        describe "Checking version for SDDC Manager: #{server['fqdn']}. Its" do
          subject { json(content: server.to_json) }
          its('version') { should match currentVersion }
        end
      end
    end
  end
end
