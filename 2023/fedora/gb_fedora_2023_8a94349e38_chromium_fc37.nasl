# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884613");
  script_version("2023-10-12T05:05:32+0000");
  script_cve_id("CVE-2022-4908", "CVE-2022-4909", "CVE-2022-4910", "CVE-2022-4906", "CVE-2022-4907", "CVE-2023-2311", "CVE-2023-2313", "CVE-2023-2929", "CVE-2023-2314", "CVE-2023-3598");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-02 03:55:00 +0000 (Wed, 02 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-05 01:10:00 +0000 (Sat, 05 Aug 2023)");
  script_name("Fedora: Security Advisory for chromium (FEDORA-2023-8a94349e38)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-8a94349e38");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/B6SAST6CB5KKCQKH75ER2UQ3ICYPHCIZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2023-8a94349e38 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium is an open-source web browser, powered by WebKit (Blink).");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 37.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~115.0.5790.110~1.fc37", rls:"FC37"))) {
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