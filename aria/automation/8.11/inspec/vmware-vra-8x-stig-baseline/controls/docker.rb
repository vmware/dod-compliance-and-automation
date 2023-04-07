include_controls 'docker' do
  # Docker daemon is not listening on a TCP port
  skip_control 'DKER-CE-000002'
  skip_control 'DKER-CE-000011'
  skip_control 'DKER-CE-000012'
  skip_control 'DKER-CE-000199'
  skip_control 'DKER-CE-000200'

  # vRA uses alternative method for managing logs
  skip_control 'DKER-CE-000031'

  # vRA uses pre-built containers, and does not pull external containers
  skip_control 'DKER-CE-000041'

  # vRA uses pre-built containers that are tuned and managed by kubernetes for application usage
  skip_control 'DKER-CE-000088'
  skip_control 'DKER-CE-000014'
  skip_control 'DKER-CE-000166'
  skip_control 'DKER-CE-000183'
  skip_control 'DKER-CE-000189'

  # vRA does not use the default bridge
  skip_control 'DKER-CE-000180'
  skip_control 'DKER-CE-000181'

  # vRA pre-configures and enables only the necessary kernel capabilities
  skip_control 'DKER-CE-000190'

  # vRA only runs pre-built and pre-configured containers, and is not a general Docker host
  skip_control 'DKER-CE-000086'
  skip_control 'DKER-CE-000087'
  skip_control 'DKER-CE-000104'
  skip_control 'DKER-CE-000191'
  skip_control 'DKER-CE-000195'
  skip_control 'DKER-CE-000197'

  # Not an SELinux OS
  skip_control 'DKER-CE-000198'
end
