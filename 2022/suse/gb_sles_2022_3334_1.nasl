# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3334.1");
  script_cve_id("CVE-2022-1996");
  script_tag(name:"creation_date", value:"2022-09-23 04:48:10 +0000 (Fri, 23 Sep 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-16 12:54:00 +0000 (Thu, 16 Jun 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3334-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3334-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223334-1/");
  script_xref(name:"URL", value:"https://github.com/kubevirt/containerized-data-importer/releases/tag/v1.51");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cdi-apiserver-container, cdi-cloner-container, cdi-controller-container, cdi-importer-container, cdi-operator-container, cdi-uploadproxy-container, cdi-uploadserver-container, containerized-data-importer' package(s) announced via the SUSE-SU-2022:3334-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cdi-apiserver-container, cdi-cloner-container,
cdi-controller-container, cdi-importer-container, cdi-operator-container,
cdi-uploadproxy-container, cdi-uploadserver-container,
containerized-data-importer fixes the following issues:

Update to version 1.51.0

Release notes [link moved to references].
 0

Security issues fixed in vendored dependencies:

CVE-2022-1996: Fixed CORS bypass (bsc#1200528)

Include additional tools used by cdi-importer: cdi-containerimage-server
 cdi-image-size-detection cdi-source-update-poller

Pack only cdi-operator and cdi-cr release manifests

Install tar for cloning filesystem PVCs");

  script_tag(name:"affected", value:"'cdi-apiserver-container, cdi-cloner-container, cdi-controller-container, cdi-importer-container, cdi-operator-container, cdi-uploadproxy-container, cdi-uploadserver-container, containerized-data-importer' package(s) on SUSE Linux Enterprise Module for Containers 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-manifests", rpm:"containerized-data-importer-manifests~1.51.0~150400.4.3.1", rls:"SLES15.0SP4"))) {
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
