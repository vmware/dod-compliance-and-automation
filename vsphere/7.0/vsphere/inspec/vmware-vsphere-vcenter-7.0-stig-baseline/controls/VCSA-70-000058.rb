control 'VCSA-70-000058' do
  title "The vCenter Server Machine SSL certificate must be issued by a DoD
certificate authority."
  desc  "The default self-signed, VMCA issued vCenter reverse proxy certificate
must be replaced with a DoD approved certificate. The use of a DoD certificate
on the vCenter reverse proxy and other services assures clients that the
service they are connecting to is legitimate and trusted."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Certificates >>
Certificate Management >> Machine SSL Certificate.  Click \"View Details\".
Examine the \"Issuer Information\" block.

    If the issuer specified is not a DoD approved certificate authority, this
is a finding.
  "
  desc 'fix', "
    Obtain a DoD issued certificate and private key for each vCenter in the
system, following the below requirements:

    Key size: 2048 bits or more (PEM encoded)
    CRT format (Base-64)
    x509 version 3
    SubjectAltName must contain DNS Name=<machine_FQDN>
    Contains the following Key Usages: Digital Signature, Non Repudiation, Key
Encipherment

    Export the entire certificate issuing chain up to the root in Base-64
format, concatenate the individual certificates into one file with \".cer\"
extension.

    From the vSphere Client, go to Administration >> Certificates >>
Certificate Management >> Machine SSL Certificate.  Click \"Actions\" >>
\"Import and Replace Certificate\". Select the \"Replace with external CA
certificate\" radio button and click \"Next\". Supply the CA issued certificate
, the exported roots file and the private key. Click \"Replace\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000058'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']
end
