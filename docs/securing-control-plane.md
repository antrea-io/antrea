# Securing Control Plane

All API communication between Antrea control plane components is encrypted with
TLS. The TLS certificates that Antrea requires can be automatically generated.
You can also provide your own certificates. This page explains the certificates
that Antrea requires and how to configure and rotate them for Antrea.

## Table of Contents
  - [What certificates are required by Antrea](#what-certificates-are-required-by-antrea)
  - [How certificates are used by Antrea](#how-certificates-are-used-by-antrea)
  - [Providing your own certificates](#providing-your-own-certificates)
    - [Using kubectl](#using-kubectl)
    - [Using cert-manager](#using-cert-manager)
  - [Certificate rotation](#certificate-rotation)

## What certificates are required by Antrea

Currently Antrea only requires a single server certificate for the
antrea-controller API server endpoint, which is for the following communication:
- The antrea-agents talks to the antrea-controller for fetching the computed
 NetworkPolicies
- The kube-aggregator (i.e. kube-apiserver) talks to the antrea-controller for
 proxying antctl's requests (when run in "controller" mode)

Antrea doesn't require client certificates for its own components as it
delegates authentication and authorization to the Kubernetes API, using
Kubernetes [ServiceAccount tokens](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#service-account-tokens)
for client authentication.

## How certificates are used by Antrea

By default, antrea-controller generates a self-signed certificate. You can
override the behavior by [providing your own certificates](#providing-your-own-certificates).
Either way, the antrea-controller will distribute the CA certificate as a
ConfigMap named `antrea-ca` in the Antrea deployment Namespace and inject it
into the APIServices resources created by Antrea in order to allow its clients
(i.e. antrea-agent, kube-apiserver) to perform authentication.

Typically, clients that wish to access the antrea-controller API can
authenticate the server by validating against the CA certificate published in
the `antrea-ca` ConfigMap.

## Providing your own certificates

Since Antrea v0.7.0, you can provide your own certificates to Antrea. To do so,
you must set the `selfSignedCert` field of `antrea-controller.conf` to `false`,
so that the antrea-controller will read the certificate key pair from the
`antrea-controller-tls` Secret. The example manifests and descriptions below
assume Antrea is deployed in the `kube-system` Namespace. If you deploy Antrea
in a different Namepace, please update the Namespace name in the manifests
accordingly.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  labels:
    app: antrea
  name: antrea-config
  namespace: kube-system
data:
  antrea-controller.conf: |
    selfSignedCert: false
```

You can generate the required certificate manually, or through
[cert-manager](https://cert-manager.io/docs/). Either way, the certificate must
be issued with the following key usages and DNS names:

X509 key usages:
- digital signature
- key encipherment
- server auth

DNS names:
- antrea.kube-system.svc
- antrea.kube-system.svc.cluster.local

**Note: It assumes you are using `cluster.local` as the cluster domain, you
should replace it with the actual one of your Kubernetes cluster.**

You can then create the `antrea-controller-tls` Secret with the certificate key
pair and the CA certificate in the following form:
```yaml
apiVersion: v1
kind: Secret
# The type can also be Opaque.
type: kubernetes.io/tls
metadata:
  name: antrea-controller-tls
  namespace: kube-system
data:
  ca.crt: <BASE64 ENCODED CA CERTIFICATE>
  tls.crt: <BASE64 ENCODED TLS CERTIFICATE>
  tls.key: <BASE64 ENCODED TLS KEY>
```

### Using kubectl

You can use `kubectl apply -f <PATH TO SECRET YAML>` to create the above secret,
or use `kubectl create secret`:

```bash
kubectl create secret generic antrea-controller-tls -n kube-system \
  --from-file=ca.crt=<PATH TO CA CERTIFICATE> --from-file=tls.crt=<PATH TO TLS CERTIFICATE> --from-file=tls.key=<PATH TO TLS KEY>
```

### Using cert-manager

If you set up [cert-manager](https://cert-manager.io/docs/) to manage your
certificates, it can be used to issue and renew the certificate required by
Antrea.

To get started, follow the [cert-manager installation documentation](
https://cert-manager.io/docs/installation/kubernetes/) to deploy cert-manager
and configure `Issuer` or `ClusterIssuer` resources.

The `Certificate` should be created in the `kube-system` namespace. For example,
A `Certificate` may look like:

```yaml
apiVersion: cert-manager.io/v1alpha2
kind: Certificate
metadata:
  name: antrea-controller-tls
  namespace: kube-system
spec:
  secretName: antrea-controller-tls
  commonName: antrea
  dnsNames:
  - antrea.kube-system.svc
  - antrea.kube-system.svc.cluster.local
  usages:
  - digital signature
  - key encipherment
  - server auth
  issuerRef:
    # Replace the name with the real Issuer you configured.
    name: ca-issuer
    # We can reference ClusterIssuers by changing the kind here.
    # The default value is Issuer (i.e. a locally namespaced Issuer)
    kind: Issuer
```

Once the `Certificate` is created, you should see the `antrea-controller-tls`
Secret created in the `kube-system` Namespace.

**Note it may take up to 1 minute for Kubernetes to propagate the Secret update
to the antrea-controller Pod if the Pod starts before the Secret is created.**

## Certificate rotation

Antrea v0.7.0 and higher supports certificate rotation. It can be achieved by
simply updating the `antrea-controller-tls` Secret. The
antrea-controller will react to the change, updating its serving certificate and
re-distributing the latest CA certificate (if applicable).

If you are using cert-manager to issue the certificate, it will renew the
certificate before expiry and update the Secret automatically.
