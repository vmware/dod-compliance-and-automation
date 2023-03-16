control 'VCSA-70-000195' do
  title 'The vCenter Server Machine Secure Sockets Layer (SSL) certificate must be issued by a DOD certificate authority.'
  desc  "
    Untrusted certificate authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DOD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DOD-approved CA, trust of this CA has not been established.

    The DOD will only accept public key infrastructure (PKI) certificates obtained from a DOD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of Transport Layer Security (TLS) certificates.

    The default self-signed, VMware Certificate Authority (VMCA)-issued vCenter reverse proxy certificate must be replaced with a DOD-approved certificate. The use of a DOD certificate on the vCenter reverse proxy and other services assures clients that the service they are connecting to is legitimate and trusted.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Certificates >> Certificate Management >> Machine SSL Certificate.

    Click \"View Details\" and examine the \"Issuer Information\" block.

    If the issuer specified is not a DOD-approved certificate authority, this is a finding.
  "
  desc 'fix', "
    Obtain a DOD-issued certificate and private key for each vCenter in the system following the requirements below:

    Key size: 2048 bits or more (PEM encoded)
    CRT format (Base-64)
    x509 version 3
    SubjectAltName must contain DNS Name=<machine_FQDN>
    Contains the following Key Usages: Digital Signature, Non Repudiation, Key Encipherment

    Export the entire certificate issuing chain up to the root in Base-64 format. Concatenate the individual certificates into one file with the \".cer\" extension.

    From the vSphere Client, go to Administration >> Certificates >> Certificate Management >> Machine SSL Certificate.

    Click Actions >> Import and Replace Certificate.

    Select the \"Replace with external CA certificate\" radio button and click \"Next\".

    Supply the CA-issued certificate , the exported roots file, and the private key.

    Click \"Replace\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000427'
  tag gid: 'V-256342'
  tag rid: 'SV-256342r885637_rule'
  tag stig_id: 'VCSA-70-000195'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']

  vcenter = powercli_command('$global:DefaultViServers.Name').stdout.strip
  describe ssl_certificate(host: "#{vcenter}", port: 443) do
    its('issuer_organization') { should cmp 'U.S. Government' }
  end
end
