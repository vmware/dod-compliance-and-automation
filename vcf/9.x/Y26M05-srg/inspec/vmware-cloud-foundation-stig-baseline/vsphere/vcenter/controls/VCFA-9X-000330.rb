control 'VCFA-9X-000330' do
  title 'The VMware Cloud Foundation vCenter Server must disable or restrict the connectivity between vSAN Health Check and public Hardware Compatibility List (HCL) by use of an external proxy server.'
  desc  'The vSAN Health Check is able to download the HCL from VMware to check compliance against the underlying vSAN Cluster hosts. To ensure the vCenter server is not directly downloading content from the internet, this functionality must be disabled. If this feature is necessary, an external proxy server must be configured.'
  desc  'rationale', ''
  desc  'check', "
    If no clusters are enabled for vSAN, this is not applicable.

    From the vSphere Client, go to Hosts and Clusters.

    Select the vCenter Server >> Configure >> vSAN >> Internet Connectivity.

    If the HCL internet download is not required, verify \"Status\" is \"Disabled\".

    If the \"Status\" is \"Enabled\", this is a finding.

    If the HCL internet download is required, verify \"Status\" is \"Enabled\" and custom proxy settings are configured.

    If \"Status\" is \"Enabled\" and a custom proxy is not configured, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the vCenter Server >> Configure >> vSAN >> Internet Connectivity.

    Click \"Edit\".

    If the HCL internet download is not required, ensure that \"Status\" is \"Disabled\".

    If the HCL internet download is required, ensure that \"Status\" is \"Enabled\" and that a custom proxy host is appropriately configured.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCFA-9X-000330'
  tag rid: 'SV-VCFA-9X-000330'
  tag stig_id: 'VCFA-9X-000330'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # Get all clusters with vSAN enabled
  clusters = powercli_command('Get-Cluster | Where-Object {$_.VsanEnabled -eq $true} | Sort-Object | Select-Object -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")

  if !clusters.blank?
    command = '$vsanphview = Get-VsanView -Id VsanPhoneHomeSystem-vsan-phonehome-system; $vsanphview.QueryVsanCloudHealthStatus() | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue'
    result = powercli_command(command).stdout.strip
    resultjson = json(content: result)

    if resultjson['InternetConnectivity'] == true
      # If internet access is enabled, verify a custom proxy server is configured.
      proxycommand = '$vsanhealthview = Get-VsanView -Id VsanVcClusterHealthSystem-vsan-cluster-health-system; $vsanhealthview.VsanHealthQueryVsanProxyConfig() | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue'
      proxyresult = powercli_command(proxycommand).stdout.strip
      proxyjson = json(content: proxyresult)
      describe 'vCenters with vSAN internet access enabled are expected to have a custom proxy configured.' do
        subject { proxyjson }
        its(['Host']) { should_not cmp 'localhost' }
      end
    else
      describe 'Enable Internet access for all vSAN clusters.' do
        subject { resultjson }
        its(['InternetConnectivity']) { should cmp 'false' }
      end
    end
  else
    impact 0.0
    describe 'No clusters with vSAN enabled found. This is not applicable.' do
      skip 'No clusters with vSAN enabled found. This is not applicable.'
    end
  end
end
