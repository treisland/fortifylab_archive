# Issue 147 sanitized MicroK8s acceptance evidence

Collected read-only on 2026-07-31 from namespace `fortify` with a 10-second
deadline. The command listed only Deployments and StatefulSets, then projected
resource kind/name, standard workload labels, container name, and image tag or
digest. Repository paths were stripped before output. It did not request Helm
values, release records, Secrets, pod data, credentials, or registry
authorization.

Observed cases exercising the contract were:

- MySQL supplied complete workload declarations and one running image;
- SSC declared chart/app and running versions different from the selected
  profile;
- ScanCentral SAST controller and sensor exposed different running version
  families (`26.2` and `25.2`);
- LIM and both SAST workloads omitted declared chart/app metadata;
- DAST workloads included multiple image roles, including images not present in
  the desired comparison allow-list.

These observations validate that real workload metadata contains match, drift,
mixed, and incomplete inputs. They do **not** establish which Helm release or
revision is installed. Installed-release evidence remains explicitly
unavailable because the observer does not read Helm storage. Missing releases,
retained workloads, and multiple revisions therefore remain a bounded gap until
a separate safe evidence source is designed and approved.
