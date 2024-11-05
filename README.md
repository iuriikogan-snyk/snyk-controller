# Snyk Admission Webhook Server

Create a Kubernetes admission webhook that integrates with Snyk to generate 'deployment-context attested' SBOMs, and, monitor container images deployed in a Kubernetes cluster, and automatically clean up relevant snyk projects when a container is deleted from a cluster.

Key Features

1. Automated SBOM Generation and Vulnerability Monitoring
   - The webhook automatically generates an SBOM in SPDX format for each container image deployed to the cluster.
   - It optionally uploads the image to Snyk Monitor for continuous vulnerability tracking as long as the image remains active in the cluster.
   - The SBOM and vulnerability data can be routed to centralized logging solutions for enhanced observability and auditing.

2. Artifact Attestation Using ORAS
   - The webhook leverages ORAS to upload the generated SBOM to the image registry as a referring artifact, attaching an attestation that includes environment and deployment metadata from the Kubernetes AdmissionReview object, including details on who requested the deployment and from where.
   - This provides a clear and traceable record of deployed container images and their associated SBOMs directly within the registry.

3. Secure Container Registry Access with External Secrets Operator (ESO)
   - ESO is configured to manage and retrieve container registry credentials securely, accessing credentials directly from cloud secret managers (AWS Secrets Manager or Azure Key Vault).
   - This ensures registry credentials are managed using IAM roles or managed identities, avoiding the need to hardcode credentials in Kubernetes configurations and aligning with best practices for cloud security.

4. Automatic Cleanup of Snyk Projects on Deployment Removal
   - When a deployment is removed from the cluster, the webhook triggers a cleanup action that automatically deletes the associated project in Snyk, keeping the Snyk dashboard organized and relevant.

5. Flexible Monitoring, Logging, and Ingress Configuration
   - Centralized logging and monitoring are configurable through Helm chart flags.

User Stories

As a DevSecOps Engineer, I want every deployed image to automatically generate and attach an SBOM and attestation to the registry so that I can track security and provenance without manual steps.
  
As a Cloud Administrator, I want secure, automated access to container registry credentials using the External Secrets Operator, so I don’t need to expose secrets within Kubernetes configurations.
  
As a Security Auditor, I need to trace deployment claims and origin information for each container image to ensure compliance with security and provenance policies

 
```plaintext
                            +----------------------------+
                            |   Kubernetes Cluster       |
                            |                            |
                            | +------------------------+ |
Deployment Created ----->   | |  Snyk Webhook Server   | |-----> Snyk API
                            | |                        | |       - Container Monitor
                            | | - SBOM Generation      | |       - SBOM Generation
                            | | - Attestation Creation | |
                            | | (Snyk project ID incl) | |
                            | +------------------------+ |
                            +----------------------------+
                                      |
                                      |
                                      v
                       +----------------------------+
                       | Container Registry         |
                       | (via ORAS)                 |
                       |                            |
                       | - Stores SBOM as Artifact  |
                       | - Stores Attestation       |
                       +----------------------------+
                                      |
                                      |
        Deployment Deleted   ---------+        Project Cleanup
                                      |
                                      v
                                Pull Image Attestation (proj id)
                                Snyk Project API
```
