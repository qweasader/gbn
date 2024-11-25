# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0238");
  script_cve_id("CVE-2024-37568");
  script_tag(name:"creation_date", value:"2024-06-26 04:11:36 +0000 (Wed, 26 Jun 2024)");
  script_version("2024-06-26T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-12 13:29:13 +0000 (Wed, 12 Jun 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0238)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0238");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0238.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33315");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-June/035616.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-authlib' package(s) announced via the MGASA-2024-0238 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Authlib before 1.3.1 has algorithm confusion with asymmetric public
keys. Unless an algorithm is specified in a jwt.decode call, HMAC
verification is allowed with any asymmetric public key. (This is similar
to CVE-2022-29217 and CVE-2024-33663.)");

  script_tag(name:"affected", value:"'python-authlib' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"python-authlib", rpm:"python-authlib~1.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-authlib", rpm:"python3-authlib~1.3.1~1.mga9", rls:"MAGEIA9"))) {
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
