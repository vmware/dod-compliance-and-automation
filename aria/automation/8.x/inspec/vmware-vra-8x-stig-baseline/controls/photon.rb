include_controls 'photon' do
  # Rsyslogd is not present on the vRA appliances and journalctl can be utilized instead to view ssh login events.
  skip_control 'PHTN-30-000007'

  # Syslog and NTP configuration is handled in the vRA Application STIG Readiness Guide content and does not need to be done at the Photon level.
  skip_control 'PHTN-30-000039'
  skip_control 'PHTN-30-000058'

  # The vRA appliances run Kubernetes/Docker to run containers that make up the services of vRA. In order to properly route traffic between containers this kernel setting cannot be disabled.
  skip_control 'PHTN-30-000106'
end
