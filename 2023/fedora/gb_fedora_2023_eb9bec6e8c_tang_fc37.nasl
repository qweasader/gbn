# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827875");
  script_version("2023-10-13T05:06:10+0000");
  script_cve_id("CVE-2023-1672");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-20 02:04:00 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-06-24 01:07:20 +0000 (Sat, 24 Jun 2023)");
  script_name("Fedora: Security Advisory for tang (FEDORA-2023-eb9bec6e8c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-eb9bec6e8c");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IVR6CQBFT65M7YKYLAC2Y442ZAESWOVV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tang'
  package(s) announced via the FEDORA-2023-eb9bec6e8c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tang is a small daemon for binding data to the presence of a third party.");

  script_tag(name:"affected", value:"'tang' package(s) on Fedora 37.");

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

  if(!isnull(res = isrpmvuln(pkg:"tang", rpm:"tang~14~1.fc37", rls:"FC37"))) {
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