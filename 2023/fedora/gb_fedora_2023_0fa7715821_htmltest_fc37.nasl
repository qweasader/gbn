# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884749");
  script_version("2023-10-12T05:05:32+0000");
  script_cve_id("CVE-2022-41717");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-12 17:50:00 +0000 (Mon, 12 Dec 2022)");
  script_tag(name:"creation_date", value:"2023-09-09 01:17:27 +0000 (Sat, 09 Sep 2023)");
  script_name("Fedora: Security Advisory for htmltest (FEDORA-2023-0fa7715821)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-0fa7715821");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/56B2FFESRYYP6IY2AZ3UWXLWKZ5IYZN4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'htmltest'
  package(s) announced via the FEDORA-2023-0fa7715821 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"htmltest runs your HTML output through a series of checks to ensure all your
links, images, scripts references work, your alt tags are filled in, et
cetera.");

  script_tag(name:"affected", value:"'htmltest' package(s) on Fedora 37.");

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

  if(!isnull(res = isrpmvuln(pkg:"htmltest", rpm:"htmltest~0.17.0~4.fc37", rls:"FC37"))) {
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