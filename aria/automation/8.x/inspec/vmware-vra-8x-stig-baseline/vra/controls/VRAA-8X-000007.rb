control 'VRAA-8X-000007' do
  title 'vRealize Automation must perform log record management.'
  desc  "
    The proper management of log records not only dictates proper archiving processes and procedures be established, it also requires allocating enough storage space to maintain the logs online for a defined period of time.

    If adequate online log storage capacity is not maintained, intrusion monitoring, security investigations, and forensic analysis can be negatively affected.

    It is important to keep a defined amount of logs online and readily available for investigative purposes. The logs may be stored on the application server until they can be archived to a log system or, in some instances, a Storage Area Network (SAN).  Regardless of the method used, log record storage capacity must be sufficient to store log data when the data cannot be offloaded to a log system or SAN.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following commands:

    1) # cat /etc/logrotate.prelude.services.conf
      Expected result:
        Define defaults for services' logs rotation: 7 iterations (one current, 6 rotated)
          rotated daily, or whenever a maximum size is exceeded. To ensure the max size triggers rotation
          whenever needed, /etc/cron.d/prelude-services-logrotate triggers logrotate for this config multiple times
          a day. Rotations are not compressed, but rotation names are parsable by logcompress. This is to allow
          logcompress to compress and rename the rotation to avoid it being deleted by logrotate which does
          not support unlimited number of rotatations.

          hourly
          rotate 6
          dateext
          dateformat .%Y%m%d%H%M%S.0
          maxsize 128M
          nocreate
          copytruncate
          nocompress
          missingok
          notifempty
          sharedscripts

          # Apply defaults for all namespaces but prelude. Some services there require different settings.
          # Since it is not an option to separate their logs in a special location and since logrotate does
          # not allow overrides, all of the services in the excluded namespaces have a dedicated config
          # in the fluentd.d directory

          /var/log/services-logs/logging/*.log
          /var/log/services-logs/default/*.log /var/log/services-logs/default/*/console-logs/*.log
          /var/log/services-logs/.orphaned/*.log /var/log/services-logs/.orphaned/*/console-logs/*.log
          /var/log/services-logs/ingress/*.log /var/log/services-logs/ingress/*/console-logs/*.log
          /var/log/services-logs/kube-node-lease/*.log /var/log/services-logs/kube-node-lease/*/console-logs/*.log
          /var/log/services-logs/kube-public/*.log /var/log/services-logs/kube-public/*/console-logs/*.log
          /var/log/services-logs/kube-system/*.log /var/log/services-logs/kube-system/*/console-logs/*.log
          /var/log/services-logs/openfaas/*.log /var/log/services-logs/openfaas/*/console-logs/*.log
          /var/log/services-logs/openfaas-fn/*.log /var/log/services-logs/openfaas-fn/*/console-logs/*.log
          /var/log/services-logs/openfaas-ip/*.log /var/log/services-logs/openfaas-ip/*/console-logs/*.log,
          /var/services-logs/*/untagged-apps/*.log /services-logs/*/untagged-apps/console-logs/*.log {
          }

          taboopat + README*
          include /etc/logrotate.prelude.services.d/

    2) List all services' logs for the prelude namespace
          ls -l /services-logs/prelude/

          Then verify that each of them is covered by an extra configuration file located in
          ls -l /etc/logrotate.prelude.services.d/

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    1) Create /etc/logrotate.prelude.services.conf  with the expected content:
          # Define defaults for services' logs rotation: 7 iterations (one current, 6 rotated)
          # rotated daily, or whenever a maximum size is exceeded. To ensure the max size triggers rotation
          # whenever needed, /etc/cron.d/prelude-services-logrotate triggers logrotate for this config multiple times
          # a day. Rotations are not compressed, but rotation names are parsable by logcompress. This is to allow
          # logcompress to compress and rename the rotation to avoid it being deleted by logrotate which does
          # not support unlimited number of rotatations.

          hourly
          rotate 6
          dateext
          dateformat .%Y%m%d%H%M%S.0
          maxsize 128M
          nocreate
          copytruncate
          nocompress
          missingok
          notifempty
          sharedscripts

          # Apply defaults for all namespaces but prelude. Some services there require different settings.
          # Since it is not an option to separate their logs in a special location and since logrotate does
          # not allow overrides, all of the services in the excluded namespaces have a dedicated config
          # in the fluentd.d directory

          /var/log/services-logs/logging/*.log
          /var/log/services-logs/default/*.log /var/log/services-logs/default/*/console-logs/*.log
          /var/log/services-logs/.orphaned/*.log /var/log/services-logs/.orphaned/*/console-logs/*.log
          /var/log/services-logs/ingress/*.log /var/log/services-logs/ingress/*/console-logs/*.log
          /var/log/services-logs/kube-node-lease/*.log /var/log/services-logs/kube-node-lease/*/console-logs/*.log
          /var/log/services-logs/kube-public/*.log /var/log/services-logs/kube-public/*/console-logs/*.log
          /var/log/services-logs/kube-system/*.log /var/log/services-logs/kube-system/*/console-logs/*.log
          /var/log/services-logs/openfaas/*.log /var/log/services-logs/openfaas/*/console-logs/*.log
          /var/log/services-logs/openfaas-fn/*.log /var/log/services-logs/openfaas-fn/*/console-logs/*.log
          /var/log/services-logs/openfaas-ip/*.log /var/log/services-logs/openfaas-ip/*/console-logs/*.log,
          /var/services-logs/*/untagged-apps/*.log /services-logs/*/untagged-apps/console-logs/*.log {
          }

          taboopat + README*
          include /etc/logrotate.prelude.services.d/

     2) For each service that is not covered by the general configuration in the /etc/logrotate.prelude.services.conf file, create a file /etc/logrotate.prelude.services.d/ns-prelude-{service-name}.lr. These files inherit from the general configuration, so unless special settings are needed, the contents of this file should look like:

     /services-logs/prelude/{service-app-name}/*.log {
      }

          Exceptions:
          * abx-service-app
    /var/log/services-logs/prelude/abx-service-app/console-logs/*.log {
        # up to 1GB a day, 7 days (1 current + 13 rotations, 512MB each)
        rotate 13
    }

          * postgres
    /var/log/services-logs/prelude/postgres-*/console-logs/*.log /var/log/services-logs/prelude/p-*/console-logs/*.log{
    }

    /var/log/services-logs/prelude/postgres-*/file-logs/postgres.log /var/log/services-logs/prelude/p-*/file-logs/postgres.log
    /var/log/services-logs/prelude/postgres-*/file-logs/repmgrd.log /var/log/services-logs/prelude/p-*/file-logs/repmgrd.log{
    }

          * provisioning-service-app
    /var/log/services-logs/prelude/provisioning-service-app/console-logs/*.log {
        # up to 7GB a day, 7 days (1 current + 97 rotations, 128MB each)
        rotate 97
    }

          * tango-blueprint-service-app
    /var/log/services-logs/prelude/tango-blueprint-service-app/console-logs/*.log {
        # up to 600MB a day, 7 days (1 current + 13 rotations, 300MB each)
        rotate 13
    }

  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000357-AS-000038'
  tag satisfies: ['SRG-APP-000092-AS-000053', 'SRG-APP-000504-AS-000229']
  tag gid: 'V-VRAA-8X-000007'
  tag rid: 'SV-VRAA-8X-000007'
  tag stig_id: 'VRAA-8X-000007'
  tag cci: ['CCI-000172', 'CCI-001464', 'CCI-001849']
  tag nist: ['AU-12 c', 'AU-14 (1)', 'AU-4']

  describe command('rpm -V prelude-symphony-logging-agent | grep -E "/etc/logrotate.prelude.services.conf|/etc/cron.d/prelude-services-logrotate"') do
    its('stdout.strip') { should cmp '' }
  end
end
