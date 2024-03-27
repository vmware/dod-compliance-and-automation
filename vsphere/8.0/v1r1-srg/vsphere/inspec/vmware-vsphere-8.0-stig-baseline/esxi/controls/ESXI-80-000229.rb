control 'ESXI-80-000229' do
  title 'The ESXi host must use DOD-approved certificates.'
  desc  "
    The default self-signed host certificate issued by the VMware Certificate Authority (VMCA) must be replaced with a DOD-approved certificate when the host will be accessed directly, such as during a virtual machine (VM) console connection.

    The use of a DOD certificate on the host assures clients the service they are connecting to is legitimate and properly secured.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> System >> Certificate.

    If the issuer is not a DOD-approved certificate authority, this is a finding.

    If the host will never be accessed directly (virtual machine console connections bypass vCenter), this is not a finding.
  "
  desc 'fix', "
    Join the ESXi host to vCenter before replacing the certificate.

    Obtain a DOD-issued certificate and private key for the host following the requirements below:

    Key size: 2048 bits or more (PEM encoded)

    Key format: PEM
    VMware supports PKCS8 and PKCS1 (RSA keys)
    x509 version 3

    SubjectAltName must contain DNS Name=<machine_FQDN>

    CRT (Base-64) format

    Contains the following Key Usages: Digital Signature, Non Repudiation, Key Encipherment

    Start time of one day before the current time

    CN (and SubjectAltName) set to the host name (or IP address) that the ESXi host has in the vCenter Server inventory

    From the vSphere Web Client, select the ESXi host's vCenter Server >> Configure >> System >> Advanced Settings.

    Select the \"vpxd.certmgmt.mode\" value and ensure it is set to \"custom\".

    Put the host into maintenance mode.

    Temporarily enable Secure Shell (SSH) on the host. Use Secure Copy Protocol (SCP) to transfer the new certificate and key to /tmp. SSH to the host. Back up the existing certificate and key:

    # mv /etc/vmware/ssl/rui.crt /etc/vmware/ssl/rui.crt.bak
    # mv /etc/vmware/ssl/rui.key /etc/vmware/ssl/rui.key.bak

    Copy the new certificate and key to \"/etc/vmware/ssl/\" and rename them to \"rui.crt\" and \"rui.key\" respectively.

    Restart management agents to implement the new certificate:

    # services.sh restart
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-ESXI-80-000229'
  tag rid: 'SV-ESXI-80-000229'
  tag stig_id: 'ESXI-80-000229'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmhostName = input('vmhostName')
  cluster = input('cluster')
  allhosts = input('allesxi')
  vmhosts = []

  unless vmhostName.empty?
    vmhosts = powercli_command("Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless cluster.empty?
    vmhosts = powercli_command("Get-Cluster -Name '#{cluster}' | Get-VMHost | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless allhosts == false
    vmhosts = powercli_command('Get-VMHost | Sort-Object Name | Select -ExpandProperty Name').stdout.split
  end

  if !vmhosts.empty?
    vmhosts.each do |vmhost|
      describe ssl_certificate(host: "#{vmhost}", port: 443) do
        its('issuer_organization') { should cmp 'U.S. Government' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
