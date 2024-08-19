control 'NMGR-4X-000094' do
  title 'The NSX Manager must obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by Office of Management and Budget (OMB) policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', '
    NSX Manager uses a certificate for each manager and one for the cluster VIP. In some cases these are the same, but each node and cluster VIP certificate must be checked individually.

    Browse to the NSX Manager web interface for each node and cluster VIP and view the certificate and its issuer of the website.

    or

    From an NSX Manager shell, run the following commands:

    > get certificate api
    > get certificate cluster

    Save the output to a .cer file to examine.

    If the certificate the NSX Manager web interface or cluster is using is not issued by an approved certificate authority and is not currently valid, this is a finding.
  '
  desc 'fix', 'Obtain a certificate or certificates signed by an approved certification authority.

This can be done individually by generating CSRs through the NSX Manager web interface >> System >> Settings >> Certificates >> CSRs >> Generate CSR or outside of NSX if a common manager and cluster certificate is desired.

Import the certificate(s) into NSX by doing the following:

From the NSX Manager web interface, go to System >> Settings >> Certificates >> Certificates >> Import >> Import Certificate. Provide a name for the certificate and paste the certificates contents and key.

Uncheck "Service Certificate" and click "Import".

After import, note the ID of the certificate(s).

Using curl or another REST API client, perform the following API calls and replace the certificate IDs noted in the previous steps.

To replace a managers certificate: POST https://<nsx-mgr>/api/v1/node/services/http?action=apply_certificate&certificate_id=e61c7537-3090-4149-b2b6-19915c20504f

To replace the cluster certificate: POST https://<nsx-mgr>/api/v1/cluster/api-certificate?action=set_cluster_certificate&certificate_id=d60c6a07-6e59-4873-8edb-339bf75711ac

Note: If an NSX Intelligence appliance is deployed with the NSX Manager cluster, update the NSX Manager node IP, certificate, and thumbprint information that is on the NSX Intelligence appliance. Refer to the VMware Knowledge Base article https://kb.vmware.com/s/article/78505 for more information.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag gid: 'V-263223'
  tag rid: 'SV-263223r977436_rule'
  tag stig_id: 'NMGR-4X-000094'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe ssl_certificate(host: "#{input('nsxManager')}", port: 443) do
    its('issuer_organization') { should cmp 'U.S. Government' }
  end
end
