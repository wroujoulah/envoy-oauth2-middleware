# envoy-oauth2-middleware

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 1.16.0](https://img.shields.io/badge/AppVersion-1.16.0-informational?style=flat-square)

A Helm chart for Kubernetes

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+
- OAuth2 provider (e.g., Cognito, Auth0, AzureAD) credentials

## Installing the Chart

Clone this repository or copy the chart files to your local machine.

To install the chart with the release name `my-release`:

```console
# From the chart's directory
helm install my-release . \
  --set envoy.config.oidc.domain=your-domain.auth.region.amazoncognito.com \
  --set envoy.config.oidc.clientId=your-client-id \
  --set envoy.config.oidc.clientSecret=your-client-secret \
  --set envoy.config.cors.allowOrigin=https://your-app.com \
  --set envoy.config.cookiesDomain=.your-domain.com \
  --set envoy.secret.hmac=your-hmac-secret
```

Alternatively, you can create a custom `values.yaml` file:

```yaml
envoy:
  config:
    oidc:
      domain: "your-domain.auth.region.amazoncognito.com"
      clientId: "your-client-id"
      clientSecret: "your-client-secret"
    cors:
      allowOrigin: "https://your-app.com"
    cookiesDomain: ".your-domain.com"
  secret:
    hmac: "your-hmac-secret"
```

And install using:

```console
helm install my-release . -f my-values.yaml
```

## Configuration

### Envoy Configuration

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `envoy.logLevel` | Log level for Envoy proxy | `"info"` | No |
| `envoy.secret.hmac` | HMAC secret for token validation | `""` | Yes |
| `envoy.config.node.id` | Node ID for Envoy configuration | `"auth_0"` | No |
| `envoy.config.node.cluster` | Cluster name for Envoy configuration | `"auth_cluster"` | No |
| `envoy.config.listener.address` | Listener address for Envoy proxy | `"0.0.0.0"` | No |
| `envoy.config.listener.port` | Listener port for Envoy proxy | `8080` | No |
| `envoy.config.cors.allowOrigin` | Allowed CORS origin | `""` | Yes |
| `envoy.config.cookiesDomain` | Cookie domain | `""` | Yes |
| `envoy.config.oidc.domain` | OAuth2 provider domain | `""` | Yes |
| `envoy.config.oidc.clientId` | OAuth2 client ID | `""` | Yes |
| `envoy.config.oidc.clientSecret` | OAuth2 client secret | `""` | Yes |
| `envoy.config.oidc.endpoint.authorize` | Authorization endpoint path | `"/oauth2/authorize"` | No |
| `envoy.config.oidc.endpoint.token` | Token endpoint path | `"/oauth2/token"` | No |
| `envoy.config.oidc.endpoint.revoke` | Token revocation endpoint path | `"/oauth2/revoke"` | No |

### Kubernetes Configuration

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `replicaCount` | Number of replicas to create | `1` | No |
| `image.repository` | Repository of the Envoy proxy image | `"envoyproxy/envoy"` | No |
| `image.tag` | Image tag | `"v1.31-latest"` | No |
| `image.pullPolicy` | Image pull policy | `"IfNotPresent"` | No |
| `imagePullSecrets` | List of image pull secrets | `[]` | No |
| `nameOverride` | String to partially override fullname template | `""` | No |
| `fullnameOverride` | String to fully override fullname template | `""` | No |
| `serviceAccount.create` | Create service account | `true` | No |
| `serviceAccount.annotations` | Service account annotations | `{}` | No |
| `serviceAccount.name` | Service account name | `""` | No |
| `service.type` | Kubernetes service type | `"ClusterIP"` | No |
| `service.port` | Service port | `8080` | No |
| `ingress.enabled` | Enable ingress controller resource | `false` | No |
| `ingress.className` | IngressClass name | `""` | No |
| `ingress.annotations` | Ingress annotations | `{}` | No |
| `resources` | Pod resource requests and limits | `{}` | No |
| `autoscaling.enabled` | Enable autoscaling | `false` | No |
| `autoscaling.minReplicas` | Minimum replicas | `1` | No |
| `autoscaling.maxReplicas` | Maximum replicas | `100` | No |
| `nodeSelector` | Node labels for pod assignment | `{}` | No |
| `tolerations` | Tolerations for pod assignment | `[]` | No |
| `affinity` | Affinity settings for pod assignment | `{}` | No |

## Uninstalling the Chart

To uninstall/delete the `my-release` deployment:

```console
helm uninstall my-release
```

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Verify your OAuth2 credentials
   - Check endpoint configurations
   - Validate HMAC secret

2. **CORS Issues**
   - Ensure `allowOrigin` is properly set
   - Verify protocol (http/https) matches

3. **Cookie Problems**
   - Check `cookiesDomain` configuration
   - Verify domain matches your application

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.11.0](https://github.com/norwoodj/helm-docs/releases/v1.11.0)