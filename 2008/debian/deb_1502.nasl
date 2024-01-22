# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60436");
  script_cve_id("CVE-2007-2821", "CVE-2007-3238", "CVE-2008-0193", "CVE-2008-0194");
  script_tag(name:"creation_date", value:"2008-02-28 01:09:28 +0000 (Thu, 28 Feb 2008)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1502-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1502-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1502-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1502");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordpress' package(s) announced via the DSA-1502-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in wordpress, a weblog manager. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-3238

Cross-site scripting (XSS) vulnerability in functions.php in the default theme in WordPress allows remote authenticated administrators to inject arbitrary web script or HTML via the PATH_INFO (REQUEST_URI) to wp-admin/themes.php.

CVE-2007-2821

SQL injection vulnerability in wp-admin/admin-ajax.php in WordPress before 2.2 allows remote attackers to execute arbitrary SQL commands via the cookie parameter.

CVE-2008-0193

Cross-site scripting (XSS) vulnerability in wp-db-backup.php in WordPress 2.0.11 and earlier allows remote attackers to inject arbitrary web script or HTML via the backup parameter in a wp-db-backup.php action to wp-admin/edit.php.

CVE-2008-0194

Directory traversal vulnerability in wp-db-backup.php in WordPress 2.0.3 and earlier allows remote attackers to read arbitrary files, delete arbitrary files, and cause a denial of service via a .. (dot dot) in the backup parameter in a wp-db-backup.php action to wp-admin/edit.php.

Wordpress is not present in the oldstable distribution (sarge).

For the stable distribution (etch), these problems have been fixed in version 2.0.10-1etch1.

We recommend that you upgrade your wordpress package.");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"2.0.10-1etch1", rls:"DEB4"))) {
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
