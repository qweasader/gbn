# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892042");
  script_cve_id("CVE-2019-19844");
  script_tag(name:"creation_date", value:"2019-12-19 03:00:08 +0000 (Thu, 19 Dec 2019)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-08 04:15:00 +0000 (Wed, 08 Jan 2020)");

  script_name("Debian: Security Advisory (DLA-2042)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-2042");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-2042");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2019/dec/18/security-releases/");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-django' package(s) announced via the DLA-2042 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a potential account hijack vulnerability in Django, the Python-based web development framework.

Django's password-reset form used a case-insensitive query to retrieve accounts matching the email address requesting the password reset. Because this typically involves explicit or implicit case transformations, an attacker who knew the email address associated with a user account could craft an email address which is distinct from the address associated with that account, but which -- due to the behavior of Unicode case transformations -- ceases to be distinct after case transformation, or which will otherwise compare equal given database case-transformation or collation behavior. In such a situation, the attacker can receive a valid password-reset token for the user account.

To resolve this, two changes were made in Django:

After retrieving a list of potentially-matching accounts from the database, Django's password reset functionality now also checks the email address for equivalence in Python, using the recommended identifier-comparison process from Unicode Technical Report 36, section 2.11.2(B)(2).

When generating password-reset emails, Django now sends to the email address retrieved from the database, rather than the email address submitted in the password-reset request form.

For more information, please see: [link moved to references].

CVE-2019-19844

Potential account hijack via password reset form

For Debian 8 Jessie, these problems have been fixed in version 1.7.11-1+deb8u8.

We recommend that you upgrade your python-django packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'python-django' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.7.11-1+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-django-common", ver:"1.7.11-1+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-django-doc", ver:"1.7.11-1+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-django", ver:"1.7.11-1+deb8u8", rls:"DEB8"))) {
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
