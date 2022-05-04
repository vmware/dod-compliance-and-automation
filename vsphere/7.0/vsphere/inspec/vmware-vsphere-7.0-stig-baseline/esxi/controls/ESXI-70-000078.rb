control 'ESXI-70-000078' do
  title 'The ESXi host must use DoD-approved certificates.'
  desc  "
    The default self-signed, VMCA issued host certificate must replaced with a DoD approved certificate when the host will be accessed directly, such during a VM console connection.

    The use of a DoD certificate on the host assures clients that the service they are connecting to is legitimate and properly secured.
  "
  desc  'rationale', ''
  desc  'check', "
    Fom the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Certificate.

    If the issuer is not a DoD-approved certificate authority, this is a finding.

    If the host will never be accessed directly (VM console connections bypass vCenter), this is not a finding.
  "
  desc 'fix', "
    Join the ESXi host to vCenter before replacing the certificate.

    Obtain a DoD-issued certificate and private key for the host following the requirements below:

    Key size: 2048 bits or more (PEM encoded)

    Key format: PEM. VMware supports PKCS8 and PKCS1 (RSA keys)
    x509 version 3

    SubjectAltName must contain DNS Name=<machine_FQDN>

    CRT (Base-64) format

    Contains the following Key Usages: Digital Signature, Non Repudiation, Key Encipherment

    Start time of one day before the current time

    CN (and SubjectAltName) set to the host name (or IP address) that the ESXi host has in the vCenter Server inventory.

    From the vSphere Web Client, select the ESXi host's vCenter Server >> Configure >> System >> Advanced Settings.

    Select the \"vpxd.certmgmt.mode\" value and make sure it is set to \"custom\".

    Put the host into maintenance mode.

    Temporarily enable SSH on the host. SCP the new certificate and key to /tmp. SSH to the host. Back up the existing certificate and key:

    # mv /etc/vmware/ssl/rui.crt /etc/vmware/ssl/rui.crt.bak
    # mv /etc/vmware/ssl/rui.key /etc/vmware/ssl/rui.key.bak

    Copy your new certificate and key to /etc/vmware/ssl/ and rename them to rui.crt and rui.key respectively.

    Restart management agents to implement the new certificate:

    # services.sh restart
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000078'
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
