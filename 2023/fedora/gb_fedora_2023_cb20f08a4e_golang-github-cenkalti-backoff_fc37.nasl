# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827592");
  script_version("2023-10-12T05:05:32+0000");
  script_cve_id("CVE-2022-41723");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-09 16:36:00 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-04-21 01:06:24 +0000 (Fri, 21 Apr 2023)");
  script_name("Fedora: Security Advisory for golang-github-cenkalti-backoff (FEDORA-2023-cb20f08a4e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-cb20f08a4e");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/H3TV3H3BVCMDSV3OJHDP2XEDXZENDIG5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-cenkalti-backoff'
  package(s) announced via the FEDORA-2023-cb20f08a4e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a Go port of the exponential backoff algorithm from Google&#39, s HTTP
Client Library for Java.

Exponential backoff is an algorithm that uses feedback to multiplicatively
decrease the rate of some process, in order to gradually find an acceptable
rate. The retries exponentially increase and stop increasing when a certain
threshold is met.");

  script_tag(name:"affected", value:"'golang-github-cenkalti-backoff' package(s) on Fedora 37.");

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

if(release == "FC37") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-cenkalti-backoff", rpm:"golang-github-cenkalti-backoff~4.2.0~2.fc37", rls:"FC37"))) {
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