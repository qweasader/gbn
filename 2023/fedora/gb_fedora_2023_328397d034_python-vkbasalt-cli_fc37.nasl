# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827766");
  script_version("2023-10-12T05:05:32+0000");
  script_cve_id("CVE-2023-22970");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-01 19:26:00 +0000 (Thu, 01 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-05-30 01:06:37 +0000 (Tue, 30 May 2023)");
  script_name("Fedora: Security Advisory for python-vkbasalt-cli (FEDORA-2023-328397d034)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-328397d034");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZJZEE4RAAK7OPVQNE4BOWUVQDVSZU6NJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-vkbasalt-cli'
  package(s) announced via the FEDORA-2023-328397d034 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"vkbasalt-cli is a CLI utility and library in conjunction with vkBasalt.
This makes generating configuration files or running vkBasalt with
games easier. This is mainly convenient in environments where
integrating vkBasalt is wishful, for example a GUI application.
Integrating vkbasalt-cli allows a front-end to easily generate and use
specific configurations on the fly, without asking the user to manually
write a configuration file.");

  script_tag(name:"affected", value:"'python-vkbasalt-cli' package(s) on Fedora 37.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-vkbasalt-cli", rpm:"python-vkbasalt-cli~3.1.1.post1~1.fc37", rls:"FC37"))) {
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