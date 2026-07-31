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
mixed, and incomplete inputs. They do **not** themselves establish which Helm
release is installed. That conclusion comes independently from the protected
root-helper snapshot, which projects bounded history metadata without values or
Secrets. Live helper collection remains to be repeated after this candidate is
installed; until then, current installed-release evidence is an explicit
deployment acceptance gap rather than an inferred result.
