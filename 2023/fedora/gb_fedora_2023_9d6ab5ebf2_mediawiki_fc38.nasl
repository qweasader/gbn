# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827503");
  script_version("2023-10-12T05:05:32+0000");
  script_cve_id("CVE-2023-29141");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-11 06:24:00 +0000 (Tue, 11 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-16 01:06:27 +0000 (Sun, 16 Apr 2023)");
  script_name("Fedora: Security Advisory for mediawiki (FEDORA-2023-9d6ab5ebf2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-9d6ab5ebf2");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ONWHGOBFD6CQAEGOP5O375XAP2N6RUHT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mediawiki'
  package(s) announced via the FEDORA-2023-9d6ab5ebf2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MediaWiki is the software used for Wikipedia and the other Wikimedia
Foundation websites. Compared to other wikis, it has an excellent
range of features and support for high-traffic websites using multiple
servers

This package supports wiki farms. Read the instructions for creating wiki
instances under /usr/share/doc/mediawiki/README.RPM.
Remember to remove the config dir after completing the configuration.");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Fedora 38.");

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

if(release == "FC38") {

  if(!isnull(res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.39.3~1.fc38", rls:"FC38"))) {
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