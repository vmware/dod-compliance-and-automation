control 'UBTU-24-600200' do
  title 'Ubuntu 24.04 LTS must configure the uncomplicated firewall to rate-limit impacted network interfaces.'
  desc 'Denial of service (DoS) occurs when a resource is not available for legitimate users, resulting in the organization not being able to accomplish its mission or causing it to operate at degraded capacity.

This requirement addresses the configuration of Ubuntu 24.04 LTS to mitigate the impact of DoS attacks that have occurred or are ongoing on system availability. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.'
  desc 'check', 'Verify an application firewall is configured to rate limit any connection to the system.

Check all the services listening to the ports with the following command:

$ ss -l46ut
Netid               State          Recv-Q          Send-Q                               Local Address:Port            Peer Address:Port               Process
tcp                 LISTEN               0                     511                                           *:http                                          *:*
tcp                 LISTEN               0                     128                                           [::]:ssh                                        [::]:*
tcp                 LISTEN               0                     128                                           [::]:ipp                                        [::]:*
tcp                 LISTEN               0                     128                                           [::]:smtp                                    [::]:*


For each entry, verify the Uncomplicated Firewall (ufw) is configured to rate limit the service ports with the following command:

$ sudo ufw status
Status: active

To                           Action     From
--                             ------         ----
80/tcp                    LIMIT       Anywhere
25/tcp                    LIMIT       Anywhere
Anywhere            DENY       177.60.7.4
443                           LIMIT      Anywhere
22/tcp                     LIMIT      Anywhere
80/tcp (v6)            LIMIT      Anywhere
25/tcp (v6)            LIMIT      Anywhere
22/tcp (v6)            LIMIT      Anywhere (v6)

25                             DENY OUT    Anywhere
25 (v6)                    DENY OUT    Anywhere (v6)

If any port with a state of "LISTEN" that does not have an action of "DENY", is not marked with the "LIMIT" action, this is a finding. If the Status is set to anything other than "active" this is a finding.'
  desc 'fix', 'Configure the application firewall to protect against or limit the effects of DoS attacks by ensuring Ubuntu 24.04 LTS is implementing rate-limiting measures on impacted network interfaces.

To change the Status of ufw to "active" use the following command:
$ sudo ufw enable

Check all the services listening to the ports with the following command:

$ sudo ss -l46ut
Netid               State                Recv-Q                Send-Q                               Local Address:Port                               Peer Address:Port               Process
tcp                 LISTEN               0                     128                                           [::]:ssh                                        [::]:*

For each service with a port listening to connections, run the following command, replacing "[service]" with the service that needs to be rate limited.

$ sudo ufw limit [service]

Rate-limiting can also be done on an interface. An example of adding a rate-limit on the eth0 interface follows:

$ sudo ufw limit in on eth0'
  impact 0.5
  tag check_id: 'C-74787r1066749_chk'
  tag severity: 'medium'
  tag gid: 'V-270754'
  tag rid: 'SV-270754r1066751_rule'
  tag stig_id: 'UBTU-24-600200'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-74688r1066750_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']

  describe 'Status listings for any allowed services, ports, or applications must be documented with the organization' do
    skip 'Status listings checks must be preformed manually'
  end
end
