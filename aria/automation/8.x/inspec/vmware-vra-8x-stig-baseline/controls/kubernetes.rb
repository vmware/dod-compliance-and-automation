include_controls 'kubernetes' do
  # vRA Kubernetes is not externally managed
  skip_control 'CNTR-K8-000150'
  skip_control 'CNTR-K8-000160'
  skip_control 'CNTR-K8-000170'
  skip_control 'CNTR-K8-000180'
  skip_control 'CNTR-K8-000190'
  skip_control 'CNTR-K8-000460'
  skip_control 'CNTR-K8-000910'
  skip_control 'CNTR-K8-001160'
  skip_control 'CNTR-K8-001300'
  skip_control 'CNTR-K8-001400'
  skip_control 'CNTR-K8-001420'
  skip_control 'CNTR-K8-001460'
  skip_control 'CNTR-K8-001470'
  skip_control 'CNTR-K8-001620'
  skip_control 'CNTR-K8-002000'
  skip_control 'CNTR-K8-002001'
  skip_control 'CNTR-K8-002010'
  skip_control 'CNTR-K8-002011'
  skip_control 'CNTR-K8-002600'
  skip_control 'CNTR-K8-003220'
  skip_control 'CNTR-K8-003340'
  skip_control 'CNTR-K8-003350'

  # SSHD is required to run InSpec tests
  skip_control 'CNTR-K8-000400'
  skip_control 'CNTR-K8-000410'

  # Handled by Photon audit policy
  skip_control 'CNTR-K8-000600'
  skip_control 'CNTR-K8-000610'
  skip_control 'CNTR-K8-000700'
  skip_control 'CNTR-K8-003280'
  skip_control 'CNTR-K8-003290'
  skip_control 'CNTR-K8-003300'
  skip_control 'CNTR-K8-003310'
  skip_control 'CNTR-K8-003320'

  # Patches and updates - managed by vRA
  skip_control 'CNTR-K8-002720'

  # Not Applicable
  skip_control 'CNTR-K8-000220'
  skip_control 'CNTR-K8-000290'
  skip_control 'CNTR-K8-000320'
  skip_control 'CNTR-K8-000330'
  skip_control 'CNTR-K8-000350'
  skip_control 'CNTR-K8-000420'
  skip_control 'CNTR-K8-000430'
  skip_control 'CNTR-K8-000440'
  skip_control 'CNTR-K8-003120'
  skip_control 'CNTR-K8-003140'
  skip_control 'CNTR-K8-003150'
  skip_control 'CNTR-K8-003260'

  # Ports and protocols
  skip_control 'CNTR-K8-000920'
  skip_control 'CNTR-K8-000930'
  skip_control 'CNTR-K8-000940'
  skip_control 'CNTR-K8-000950'
  skip_control 'CNTR-K8-000960'

  # Namespace check
  skip_control 'CNTR-K8-001360'
end
