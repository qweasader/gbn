# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1234.1");
  script_cve_id("CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875", "CVE-2019-5736", "CVE-2019-6486");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:25 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-01 20:15:00 +0000 (Thu, 01 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1234-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1234-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191234-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'containerd, docker, docker-runc, go, go1.11, go1.12, golang-github-docker-libnetwork' package(s) announced via the SUSE-SU-2019:1234-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for containerd, docker, docker-runc, go, go1.11, go1.12,
golang-github-docker-libnetwork fixes the following issues:

Security issues fixed:

CVE-2019-5736: containerd: Fixing container breakout vulnerability
 (bsc#1121967).

CVE-2019-6486: go security release, fixing crypto/elliptic CPU DoS
 vulnerability affecting P-521 and P-384 (bsc#1123013).

CVE-2018-16873: go security release, fixing cmd/go remote command
 execution (bsc#1118897).

CVE-2018-16874: go security release, fixing cmd/go directory traversal
 (bsc#1118898).

CVE-2018-16875: go security release, fixing crypto/x509 CPU denial of
 service (bsc#1118899).

Other changes and bug fixes:

Update to containerd v1.2.5, which is required for v18.09.5-ce
 (bsc#1128376, bsc#1134068).

Update to runc 2b18fe1d885e, which is required for Docker v18.09.5-ce
 (bsc#1128376, bsc#1134068).

Update to Docker 18.09.5-ce see upstream changelog in the packaged
 (bsc#1128376, bsc#1134068).

docker-test: Improvements to test packaging (bsc#1128746).

Move daemon.json file to /etc/docker directory (bsc#1114832).

Revert golang(API) removal since it turns out this breaks >= requires in
 certain cases (bsc#1114209).

Fix go build failures (bsc#1121397).");

  script_tag(name:"affected", value:"'containerd, docker, docker-runc, go, go1.11, go1.12, golang-github-docker-libnetwork' package(s) on SUSE Linux Enterprise Module for Containers 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.2.5~5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~18.09.6_ce~6.17.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~18.09.6_ce~6.17.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~18.09.6_ce~6.17.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debugsource", rpm:"docker-debugsource~18.09.6_ce~6.17.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork", rpm:"docker-libnetwork~0.7.0.1+gitr2726_872f0a83c98a~4.12.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork-debuginfo", rpm:"docker-libnetwork-debuginfo~0.7.0.1+gitr2726_872f0a83c98a~4.12.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc", rpm:"docker-runc~1.0.0rc6+gitr3804_2b18fe1d885e~6.18.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc-debuginfo", rpm:"docker-runc-debuginfo~1.0.0rc6+gitr3804_2b18fe1d885e~6.18.1", rls:"SLES15.0"))) {
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
