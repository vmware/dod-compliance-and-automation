# Install Gatekeeper
In order to restrict which repository can be used in your cluster please install OPA Gatekeeper onto your cluster. Full helm install instructions [here](https://open-policy-agent.github.io/gatekeeper/website/docs/install#deploying-via-helm)

```sh
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.5.2/deploy/experimental/gatekeeper-mutation.yaml
```
## Restricting Docker Registry
### Apply Template and Constraint
Once gatekeeper is installed you simply need to apply the [repo/template.yaml](repo/template.yaml).
```sh
kubectl apply -f repo/template.yaml
```
Then you will need to modify the [repo/constraint.yaml](repo/template.yaml). to update line 14 to point at your repo. If you are not running in an air gapped environment you will need to add a 2nd item to the repos array for "projects.registry.vmware.com/"

```sh
kubectl apply -f repo/constraint.yaml
```

## Pod Security Policies
All of the pod security policies are stored within the psp folder. They are broken up into subfolders by type. The constraint template folder applies all of the rego templates for the rules. The contraint folder contains constraints are applied against the templates with the inputs provided in the constraint yaml. These two combine to provide pod security on the cluster. The mutations folder contains mutations to fix some tkg or open source pod yamls so that they start as expected or to set a default for security contexts on all pods where one is not provided.

To apply pod security to the cluster run the following from the directory you clone this repository to:
For tkg 1.x:
```sh
cd tkg
```
or for tkg 2.x:
```sh
cd tkg2
```
After you chose your version run the below:
`kubectl apply -f psp/constraint-templates` `kubectl apply -f mutations -R` and then wait a few minutes until you see all of the contrainttemplates with `kubectl get constrainttemplates` and then run `kubectl apply -f psp/constraints`

This will enfore the following:

1) runAsUser: MustRunAsNonRoot
2) runAsGroup: MustRunAs 1 to 65535
3) fsGroup: MayRunAs 1 to 65535 (No fsGroup is set if not needed)
4) supplementalGroup: MayRunAs 1 to 65536 (No supplemental Groups set if not needed)
5) priveleged: false
6) allowPrivelegedEsclation: false
7) readOnlyRootFilesystem: true
8) volumes: configMap, emptyDir, projected, secret, downwardAPI, persistentVolumeClaim
9) capabilities: drop All
10) hostNetwork: false
11) hostPorts: none
12) hostPID: false
13) hostIPC: false

All of the rules exclude the gatekeeper-system and kube-system namespaces and several of them exclude tanzu-system-ingress for the ingress controller and tanzu-system-logging for log forwarding to an external system. Tkg-system is excluded from hostNetwork as  the kapp-controller runs on the host.

## Resource Policies

Gatekeeper mutations to set default limits and requests on all pods in the cluster outside of kube-system are stored within `resource-policies/mutations`. The defaults will be set to the following:

```yaml
resources:
  limits: 
    cpu: "4"
    memory: "5Gi"
  requests:
    cpu: "200m"
    memory: "100Mi"
```

If the resources section for requests or limits is set they will be used over the defaults set in the mutation.

## Automount Service Account Tokens

A Gatekeeper mutation to set the default for automountServiceAccountToken on all pods to false is set to false is stored in `automount-sa/mutations/mutation.yaml`. If the automountServiceAccountToken is set to true it will be not be reverted. A projected volume with the service account token can be added to the pods if needed without setting automountServiceAccountToken to true. The projected volume allows the token to rotate after an expiration period and is the recommended approach.



# **Important Note**

All pods created before the gatekeeper constraints and mutations were created will continue to run even if they are not in compliance. In order to fix this it is recommended to restart all pods not in the gatekeeper system after creation of these rules.