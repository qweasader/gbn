# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0049");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2023-0049)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0049");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0049.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31527");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/news/2023/2/8/phpmyadmin-4911-and-521-are-released/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpmyadmin' package(s) announced via the MGASA-2023-0049 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for an XSS vulnerability in the drag-and-drop upload
functionality (PMASA-2023-01)

Additional bugfixes including -
 issue #17506 Fix error when configuring 2FA without XMLWriter or Imagick
 issue #17519 Fix Export pages not working in certain conditions
 issue #17121 Fix password_hash function incorrectly adding single quotes
 to password before hashing
 issue #17736 Add utf8mb3 as an alias of utf8 on the charset description
 page
 issue #17248 Support the UUID data type for MariaDB >= 10.7
 issue #16042 Fixes malformed downloads when using gzip compression type
 and FireFox browser
 Add `spellcheck='false'` to all password fields and some text fields to
 avoid spell-jacking data leaks
 Fixes for JavaScript errors when using Designer
 Fixes for PHP 8.2 compatibility");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"phpmyadmin", rpm:"phpmyadmin~5.2.1~1.mga8", rls:"MAGEIA8"))) {
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
