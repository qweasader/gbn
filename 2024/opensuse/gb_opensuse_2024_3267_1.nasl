# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856481");
  script_version("2024-09-25T05:06:11+0000");
  script_cve_id("CVE-2023-45142", "CVE-2024-6104");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-18 18:27:50 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"creation_date", value:"2024-09-18 04:01:20 +0000 (Wed, 18 Sep 2024)");
  script_name("openSUSE: Security Advisory for SUSE Manager Client Tools (SUSE-SU-2024:3267-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3267-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LVIWDYYN6LLZLFD7GR7LHE73UYRYDPHX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Manager Client Tools'
  package(s) announced via the SUSE-SU-2024:3267-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

  golang-github-prometheus-prometheus:

  * Security issues fixed:

  * CVE-2024-6104: Update go-retryablehttp to version 0.7.7 (bsc#1227038)

  * CVE-2023-45142: Updated otelhttp to version 0.46.1 (bsc#1228556)

  * Require Go > 1.20 for building

  * Migrate from `disabled` to `manual` service mode

  * Update to 2.45.6 (jsc#PED-3577):

  * Security fixes in dependencies

  * Update to 2.45.5:

  * [BUGFIX] tsdb/agent: ensure that new series get written to WAL on rollback.

  * [BUGFIX] Remote write: Avoid a race condition when applying configuration.

  * Update to 2.45.4:

  * [BUGFIX] Remote read: Release querier resources before encoding the results.

  * Update to 2.45.3:

  * [BUGFIX] TSDB: Remove double memory snapshot on shutdown.

  * Update to 2.45.2:

  * [BUGFIX] TSDB: Fix PostingsForMatchers race with creating new series.

  * Update to 2.45.1:

  * [ENHANCEMENT] Hetzner SD: Support larger ID's that will be used by Hetzner
      in September.

  * [BUGFIX] Linode SD: Cast InstanceSpec values to int64 to avoid overflows on
      386 architecture.

  * [BUGFIX] TSDB: Handle TOC parsing failures.

  rhnlib:

  * Version 5.0.4-0

  * Add the old TLS code for very old traditional clients still on python 2.7
      (bsc#1228198)

  spacecmd:

  * Version 5.0.9-0

  * Update translation strings

  uyuni-tools:

  * Version 0.1.21-0

  * mgrpxy: Fix typo on Systemd template

  * Version 0.1.20-0

  * Update the push tag to 5.0.1

  * mgrpxy: expose port on IPv6 network (bsc#1227951)

  * Version 0.1.19-0

  * Skip updating Tomcat remote debug if conf file is not present

  * Version 0.1.18-0

  * Setup Confidential Computing container during migration (bsc#1227588)

  * Add the /etc/uyuni/uyuni-tools.yaml path to the config help

  * Split systemd config files to not loose configuration at upgrade
      (bsc#1227718)

  * Use the same logic for image computation in mgradm and mgrpxy (bsc#1228026)

  * Allow building with different Helm and container default registry paths
      (bsc#1226191)

  * Fix recursion in mgradm upgrade podman list --help

  * Setup hub xmlrpc API service in migration to Podman (bsc#1227588)

  * Setup disabled hub xmlrpc API service in all cases (bsc#1227584)

  * Clean the inspection code to make it faster

  * Properly detect IPv6 enabled on Podman network (bsc#1224349)

  * Fix the log file path generation

  * Write scripts output to uyuni-tools.log file

  * Add uyuni-hubxml-rp ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'SUSE Manager Client Tools' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~5.0.9~150000.3.124.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~5.0.9~150000.3.124.1", rls:"openSUSELeap15.5"))) {
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