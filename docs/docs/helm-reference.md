# Helm Reference

Deploy the AumOS Auth Gateway to Kubernetes using the official Helm chart.

```bash
helm upgrade --install aumos-auth-gateway oci://ghcr.io/aumos/helm-charts/aumos-auth-gateway \
  --namespace aumos \
  --create-namespace \
  --values values-production.yaml
```

## Values reference

| Key | Default | Description |
|-----|---------|-------------|
| `image.repository` | `ghcr.io/aumos/aumos-auth-gateway` | Container image repository |
| `image.tag` | `latest` | Image tag |
| `replicaCount` | `2` | Number of pod replicas |
| `resources.requests.cpu` | `250m` | CPU request |
| `resources.requests.memory` | `256Mi` | Memory request |
| `resources.limits.cpu` | `1000m` | CPU limit |
| `resources.limits.memory` | `512Mi` | Memory limit |
| `service.type` | `ClusterIP` | Kubernetes service type |
| `service.port` | `8000` | Service port |
| `keycloak.baseUrl` | `""` | Keycloak server URL (required) |
| `keycloak.adminPassword` | `""` | Admin password (use secret ref) |
| `keycloak.audience` | `aumos-platform` | JWT audience claim |
| `keycloak.aumos_realm` | `aumos` | AumOS Keycloak realm name |
| `opa.baseUrl` | `http://opa:8181` | OPA server URL |
| `kong.adminUrl` | `http://kong:8001` | Kong Admin API URL |
| `database.url` | `""` | PostgreSQL async DSN (required) |
| `kafka.bootstrapServers` | `""` | Kafka broker list (required) |
| `k8s.apiUrl` | `https://kubernetes.default.svc` | K8s API for token exchange |
| `autoscaling.enabled` | `false` | Enable HPA |
| `autoscaling.minReplicas` | `2` | HPA minimum replicas |
| `autoscaling.maxReplicas` | `10` | HPA maximum replicas |

## Production values example

```yaml
replicaCount: 3

image:
  repository: ghcr.io/aumos/aumos-auth-gateway
  tag: "1.0.0"

resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: 2000m
    memory: 1Gi

keycloak:
  baseUrl: "https://keycloak.internal.aumos.ai"
  audience: aumos-platform
  aumos_realm: aumos

opa:
  baseUrl: "http://opa.aumos.svc:8181"

kong:
  adminUrl: "http://kong-admin.aumos.svc:8001"

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
  targetCPUUtilizationPercentage: 70
```
