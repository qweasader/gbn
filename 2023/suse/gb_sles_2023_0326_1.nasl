# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0326.1");
  script_cve_id("CVE-2021-20199", "CVE-2021-20206", "CVE-2021-4024", "CVE-2021-41190", "CVE-2022-21698", "CVE-2022-27191", "CVE-2022-27649", "CVE-2022-2989");
  script_tag(name:"creation_date", value:"2023-02-10 04:34:56 +0000 (Fri, 10 Feb 2023)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-13 17:07:59 +0000 (Wed, 13 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0326-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0326-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230326-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'podman' package(s) announced via the SUSE-SU-2023:0326-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for podman fixes the following issues:

podman was updated to version 4.3.1:

4.3.1:

Bugfixes

Fixed a deadlock between the `podman ps` and `podman container inspect`
 commands

Misc

Updated the containers/image library to v5.23.1

4.3.0:

Features

A new command, `podman generate spec`, has been added, which creates a
 JSON struct based on a given container that can be used with the Podman
 REST API to create containers.

A new command, `podman update`, has been added,which makes changes to
 the resource limits of existing containers. Please note that these
 changes do not persist if the container is restarted

A new command, `podman kube down`, has been added, which removes pods
 and containers created by the given Kubernetes YAML (functionality is
 identical to `podman kube play --down`, but it now has its own command).

The `podman kube play` command now supports Kubernetes secrets using
 Podman's secrets backend.

Systemd-managed pods created by the `podman kube play` command now
 integrate with sd-notify, using the `io.containers.sdnotify` annotation
 (or `io.containers.sdnotify/$name` for specific containers).

Systemd-managed pods created by `podman kube play` can now be
 auto-updated, using the `io.containers.auto-update` annotation (or
 `io.containers.auto-update/$name` for specific containers).

The `podman kube play` command can now read YAML from URLs, e.g. `podman
 kube play https://example.com/demo.yml`

The `podman kube play` command now supports the `emptyDir` volume type

The `podman kube play` command now supports the `HostUsers` field in the
 pod spec.

The `podman play kube` command now supports `binaryData` in ConfigMaps.

The `podman pod create` command can now set additional resource limits
 for pods using the new `--memory-swap`, `--cpuset-mems`,
 `--device-read-bps`, `--device-write-bps`, `--blkio-weight`,
 `--blkio-weight-device`, and `--cpu-shares` options.

The `podman machine init` command now supports a new option,
 `--username`, to set the username that will be used to connect to the VM
 as a non-root user

The `podman volume create` command's `-o timeout=` option can now set a
 timeout of 0, indicating volume plugin operations will never time out.

Added support for a new volume driver, `image`, which allows volumes to
 be created that are backed by images.

The `podman run` and `podman create` commands support a new option,
 `--env-merge`, allowing environment variables to be specified relative
 to other environment variables in the image (e.g. `podman run
 --env-merge 'PATH=$PATH:/my/app' ...`)

The `podman run` and `podman create` commands support a new option,
 `--on-failure`, to allow action to be taken when a container fails
 health checks, with the following supported actions: `none` (take no
 action, the default), `kill` (kill the container), `restart` (restart
 the container), and `stop` (stop the container).

The ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'podman' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP 15-SP3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~4.3.1~150300.9.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-cni-config", rpm:"podman-cni-config~4.3.1~150300.9.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
